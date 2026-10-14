//! Beacon-node HTTP client: the chain parameters for signing, the beacon
//! block an execution payload belongs to, and proof submission
//! (`POST /eth/v1/beacon/execution_proofs`, beacon-APIs PR #660).

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use tracing::{debug, warn};

use crate::ssz::{encode_signed_list, Root, SignedExecutionProofEnvelope};

pub struct BeaconClient {
    http: reqwest::Client,
    url: String,
}

/// What signing needs from the beacon chain, read once at startup.
pub struct ChainParams {
    pub genesis_validators_root: Root,
    pub slots_per_epoch: u64,
    /// `DEPOSIT_CHAIN_ID`: the `chain_id` of the proofs' `PublicInput`.
    pub deposit_chain_id: u64,
    /// `(activation epoch, fork version)`, ascending by epoch.
    pub forks: Vec<(u64, [u8; 4])>,
}

impl ChainParams {
    /// The fork version at `slot`'s epoch.
    pub fn fork_version_at_slot(&self, slot: u64) -> [u8; 4] {
        let epoch = slot / self.slots_per_epoch;
        self.forks
            .iter()
            .take_while(|(e, _)| *e <= epoch)
            .last()
            .map(|(_, v)| *v)
            .unwrap_or(self.forks[0].1)
    }
}

fn root_from_hex(s: &str) -> Result<Root> {
    let b = hex::decode(s.trim_start_matches("0x")).with_context(|| format!("bad hex {s}"))?;
    b.try_into().map_err(|_| anyhow::anyhow!("not 32 bytes: {s}"))
}

fn num(v: &Value) -> Result<u64> {
    v.as_str()
        .context("expected a quoted number")?
        .parse()
        .context("expected a quoted number")
}

impl BeaconClient {
    pub fn new(url: &str) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        Ok(Self { http, url: url.trim_end_matches('/').to_string() })
    }

    async fn get(&self, path: &str) -> Result<Option<Value>> {
        let resp = self.http.get(format!("{}{path}", self.url)).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = resp.status();
        if !status.is_success() {
            bail!("GET {path}: {status}: {}", resp.text().await.unwrap_or_default());
        }
        Ok(Some(resp.json::<Value>().await?["data"].clone()))
    }

    async fn get_required(&self, path: &str) -> Result<Value> {
        self.get(path).await?.with_context(|| format!("GET {path}: not found"))
    }

    pub async fn chain_params(&self) -> Result<ChainParams> {
        let spec = self.get_required("/eth/v1/config/spec").await?;
        let genesis = self.get_required("/eth/v1/beacon/genesis").await?;
        let version = |s: &Value| -> Result<[u8; 4]> {
            let b = hex::decode(s.as_str().context("fork version")?.trim_start_matches("0x"))?;
            b.try_into().map_err(|_| anyhow::anyhow!("fork version is not 4 bytes"))
        };
        let obj = spec.as_object().context("spec is not an object")?;
        let mut forks = vec![(0, version(&spec["GENESIS_FORK_VERSION"])?)];
        for (k, v) in obj {
            if let Some(name) = k.strip_suffix("_FORK_VERSION") {
                if name == "GENESIS" {
                    continue;
                }
                let epoch = num(&spec[format!("{name}_FORK_EPOCH")])?;
                if epoch != u64::MAX {
                    forks.push((epoch, version(v)?));
                }
            }
        }
        forks.sort();
        Ok(ChainParams {
            genesis_validators_root: root_from_hex(
                genesis["genesis_validators_root"].as_str().context("genesis_validators_root")?,
            )?,
            slots_per_epoch: num(&spec["SLOTS_PER_EPOCH"])?,
            deposit_chain_id: num(&spec["DEPOSIT_CHAIN_ID"])?,
            forks,
        })
    }

    /// The index of the validator with `pubkey`, which must be active.
    pub async fn validator_index(&self, pubkey: &[u8; 48]) -> Result<u64> {
        let path = format!("/eth/v1/beacon/states/head/validators/0x{}", hex::encode(pubkey));
        let v = self
            .get(&path)
            .await?
            .with_context(|| format!("0x{} is not a validator", hex::encode(pubkey)))?;
        let status = v["status"].as_str().unwrap_or_default();
        if !status.starts_with("active") {
            bail!("validator 0x{} is {status}, not active", hex::encode(pubkey));
        }
        num(&v["index"])
    }

    /// The root of the beacon block at `slot` whose execution payload bid
    /// commits to `block_hash` (Gloas: the EL header's `slot_number`).
    /// `None` if the slot has no such block (yet).
    pub async fn beacon_root_for_payload(&self, slot: u64, block_hash: &Root) -> Result<Option<Root>> {
        let Some(root) = self.get(&format!("/eth/v1/beacon/blocks/{slot}/root")).await? else {
            return Ok(None);
        };
        let root = root_from_hex(root["root"].as_str().context("root")?)?;
        let Some(block) = self.get(&format!("/eth/v2/beacon/blocks/0x{}", hex::encode(root))).await? else {
            return Ok(None);
        };
        let bid_hash = &block["message"]["body"]["signed_execution_payload_bid"]["message"]["block_hash"];
        let Some(bid_hash) = bid_hash.as_str() else {
            bail!("beacon block at slot {slot} has no execution payload bid (pre-Gloas?)");
        };
        if root_from_hex(bid_hash)? != *block_hash {
            debug!(slot, bid_hash, "beacon block at the slot commits to another payload");
            return Ok(None);
        }
        Ok(Some(root))
    }

    /// `beacon_root_for_payload`, retried until `timeout` (the payload can
    /// reach the EL before the CL has imported the block that commits to it).
    pub async fn wait_beacon_root(&self, slot: u64, block_hash: &Root, timeout: Duration) -> Result<Root> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.beacon_root_for_payload(slot, block_hash).await {
                Ok(Some(root)) => return Ok(root),
                Ok(None) => {}
                Err(e) => warn!(slot, "beacon block lookup: {e:#}"),
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("no beacon block at slot {slot} commits to payload 0x{}", hex::encode(block_hash));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// `POST /eth/v1/beacon/execution_proofs` (SSZ body). A proof the node
    /// has already seen is a success.
    pub async fn submit(&self, proofs: &[SignedExecutionProofEnvelope]) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/eth/v1/beacon/execution_proofs", self.url))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(encode_signed_list(proofs))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            bail!("POST execution_proofs: {status}: {}", resp.text().await.unwrap_or_default());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_version_lookup() {
        let p = ChainParams {
            genesis_validators_root: [0; 32],
            slots_per_epoch: 32,
            deposit_chain_id: 11155111,
            forks: vec![(0, [0x90, 0, 0, 0x69]), (272640, [0x90, 0, 0, 0x75]), (353024, [0x90, 0, 0, 0x76])],
        };
        assert_eq!(p.fork_version_at_slot(353024 * 32 - 1), [0x90, 0, 0, 0x75]);
        assert_eq!(p.fork_version_at_slot(353024 * 32), [0x90, 0, 0, 0x76]);
        assert_eq!(p.fork_version_at_slot(11353509), [0x90, 0, 0, 0x76]);
    }
}
