//! Lighthouse-direct payload source (`--zisk.lighthouse-early`): on the
//! beacon node's `execution_payload_gossip` event (the payload envelope
//! arrived over gossip), fetch the envelope from the beacon API and hand
//! the payload to the pipeline, possibly before Lighthouse has called
//! newPayload on the EL. The pipeline starts on whichever source is first.

use std::time::{Duration, Instant, SystemTime};

use alloy_eips::eip7685::Requests;
use alloy_primitives::{Bytes, B256};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar, ExecutionPayloadV4,
    PraguePayloadFields,
};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use reth_ethereum::primitives::SealedBlock;
use reth_ethereum::TransactionSigned;
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::pipeline::Incoming;

/// Follow the beacon node's gossip events forever, reconnecting on errors.
pub async fn run(beacon_url: String, tx: mpsc::Sender<Incoming>) {
    let http = reqwest::Client::new();
    loop {
        if let Err(e) = follow(&http, &beacon_url, &tx).await {
            warn!("lighthouse event stream: {e:#}; reconnecting");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn follow(http: &reqwest::Client, url: &str, tx: &mpsc::Sender<Incoming>) -> Result<()> {
    let resp = http
        .get(format!("{url}/eth/v1/events?topics=execution_payload_gossip"))
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await?
        .error_for_status()?;
    info!("following lighthouse execution_payload_gossip events");
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        buf.extend_from_slice(&chunk?);
        while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            let Some(data) = std::str::from_utf8(&line).ok().and_then(|l| l.trim().strip_prefix("data:")) else {
                continue;
            };
            let gossip_at = SystemTime::now();
            let v: Value = serde_json::from_str(data.trim())?;
            let root = v["block_root"].as_str().context("block_root")?.to_string();
            let (http, url, tx) = (http.clone(), url.to_string(), tx.clone());
            tokio::spawn(async move {
                match fetch_payload(&http, &url, &root).await {
                    Ok((block, bal, beacon_root)) => {
                        let incoming = Incoming {
                            block,
                            bal: Some(bal),
                            beacon_root: Some(beacon_root.0),
                            source: "lh_envelope",
                            at: SystemTime::now(),
                            extra_marks: vec![("lh_gossip", gossip_at)],
                        };
                        let _ = tx.send(incoming).await;
                    }
                    Err(e) => warn!(%root, "lighthouse envelope: {e:#}"),
                }
            });
        }
    }
    bail!("event stream ended")
}

/// The envelope of beacon block `root`, retried until the node serves it.
async fn fetch_payload(http: &reqwest::Client, url: &str, root: &str) -> Result<(SealedBlock<reth_ethereum::Block>, Bytes, B256)> {
    let t = Instant::now();
    let path = format!("{url}/eth/v1/beacon/execution_payload_envelopes/{root}");
    let v: Value = loop {
        let resp = http.get(&path).send().await?;
        if resp.status().is_success() {
            break resp.json().await?;
        }
        if t.elapsed() > Duration::from_secs(1) {
            bail!("envelope not served after 1 s ({})", resp.status());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    debug!(root, elapsed = ?t.elapsed(), "fetched envelope");
    envelope_to_block(&v["data"]["message"])
}

/// Beacon-API JSON (snake_case, decimal strings) → engine-API JSON
/// (camelCase, hex quantities), the shape alloy's types deserialize.
fn to_engine_json(v: &Value) -> Value {
    fn camel(k: &str) -> String {
        let mut out = String::new();
        let mut up = false;
        for c in k.chars() {
            if c == '_' {
                up = true;
            } else if up {
                out.extend(c.to_uppercase());
                up = false;
            } else {
                out.push(c);
            }
        }
        out
    }
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (camel(k), to_engine_json(v))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(to_engine_json).collect()),
        // Decimal strings are quantities; hex strings stay as they are.
        Value::String(s) if !s.starts_with("0x") && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            let n: alloy_primitives::U256 = s.parse().unwrap_or_default();
            Value::String(format!("{n:#x}"))
        }
        other => other.clone(),
    }
}

fn hex_field(v: &Value, k: &str) -> Result<Vec<u8>> {
    let s = v[k].as_str().with_context(|| format!("field {k}"))?;
    Ok(hex::decode(s.trim_start_matches("0x"))?)
}

fn u64_field(v: &Value, k: &str) -> Result<u64> {
    v[k].as_str().with_context(|| format!("field {k}"))?.parse().with_context(|| format!("field {k}"))
}

/// EIP-7685 requests (`type || records`) from the envelope's typed lists.
fn requests(r: &Value) -> Result<Requests> {
    let mut out = Vec::new();
    let mut push = |ty: u8, items: &Value, encode: &dyn Fn(&Value, &mut Vec<u8>) -> Result<()>| -> Result<()> {
        let items = items.as_array().map(Vec::as_slice).unwrap_or_default();
        if items.is_empty() {
            return Ok(());
        }
        let mut b = vec![ty];
        for it in items {
            encode(it, &mut b)?;
        }
        out.push(Bytes::from(b));
        Ok(())
    };
    push(0x00, &r["deposits"], &|d, b| {
        b.extend(hex_field(d, "pubkey")?);
        b.extend(hex_field(d, "withdrawal_credentials")?);
        b.extend(u64_field(d, "amount")?.to_le_bytes());
        b.extend(hex_field(d, "signature")?);
        b.extend(u64_field(d, "index")?.to_le_bytes());
        Ok(())
    })?;
    push(0x01, &r["withdrawals"], &|w, b| {
        b.extend(hex_field(w, "source_address")?);
        b.extend(hex_field(w, "validator_pubkey")?);
        b.extend(u64_field(w, "amount")?.to_le_bytes());
        Ok(())
    })?;
    push(0x02, &r["consolidations"], &|c, b| {
        b.extend(hex_field(c, "source_address")?);
        b.extend(hex_field(c, "source_pubkey")?);
        b.extend(hex_field(c, "target_pubkey")?);
        Ok(())
    })?;
    // EIP-8282 builder requests: field names not pinned down yet; let the
    // engine tap handle such blocks.
    for k in ["builder_deposits", "builder_exits"] {
        if r[k].as_array().is_some_and(|a| !a.is_empty()) {
            bail!("envelope has {k}; not converted");
        }
    }
    Ok(Requests::new(out))
}

/// The sealed block, BAL and beacon block root of a payload envelope; the
/// block hash is recomputed and must match the payload's.
fn envelope_to_block(msg: &Value) -> Result<(SealedBlock<reth_ethereum::Block>, Bytes, B256)> {
    let payload_json = &msg["payload"];
    let v4: ExecutionPayloadV4 =
        serde_json::from_value(to_engine_json(payload_json)).context("decoding the envelope payload")?;
    let expected: B256 = v4.payload_inner.payload_inner.payload_inner.block_hash;
    let bal = v4.block_access_list.clone();
    let parent_beacon_block_root: B256 =
        msg["parent_beacon_block_root"].as_str().context("parent_beacon_block_root")?.parse()?;
    let beacon_root: B256 = msg["beacon_block_root"].as_str().context("beacon_block_root")?.parse()?;

    let txs = &v4.payload_inner.payload_inner.payload_inner.transactions;
    let mut versioned_hashes = Vec::new();
    for raw in txs {
        use alloy_consensus::Transaction as _;
        use alloy_eips::eip2718::Decodable2718;
        let tx = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_ref())?;
        if let Some(h) = tx.blob_versioned_hashes() {
            versioned_hashes.extend_from_slice(h);
        }
    }
    let sidecar = ExecutionPayloadSidecar::v4(
        CancunPayloadFields { parent_beacon_block_root, versioned_hashes },
        PraguePayloadFields::new(requests(&msg["execution_requests"])?),
    );
    let data = ExecutionData { payload: ExecutionPayload::V4(v4), sidecar };
    let block = data.try_into_block::<TransactionSigned>().map_err(|e| anyhow::anyhow!("payload to block: {e}"))?;
    let sealed = SealedBlock::seal_slow(block);
    if sealed.hash() != expected {
        bail!("envelope block hash mismatch: computed {}, payload says {expected}", sealed.hash());
    }
    Ok((sealed, bal, beacon_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_json() {
        let v = serde_json::json!({"block_number": "11913310", "extra_data": "0xd883", "base_fee_per_gas": "17",
                                   "withdrawals": [{"validator_index": "1306"}]});
        assert_eq!(
            to_engine_json(&v),
            serde_json::json!({"blockNumber": "0xb5c85e", "extraData": "0xd883", "baseFeePerGas": "0x11",
                               "withdrawals": [{"validatorIndex": "0x51a"}]})
        );
    }
}

#[cfg(test)]
mod envelope_file_test {
    /// `ZISK_ENVELOPE_JSON=<file> cargo test -- --ignored envelope_file`:
    /// a saved `execution_payload_envelopes` response converts and its
    /// recomputed block hash matches.
    #[test]
    #[ignore]
    fn envelope_file() {
        let path = std::env::var("ZISK_ENVELOPE_JSON").expect("ZISK_ENVELOPE_JSON");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let (block, bal, root) = super::envelope_to_block(&v["data"]["message"]).unwrap();
        println!("block {} {} txs, bal {} B, beacon root {root}", block.number, block.body().transactions.len(), bal.len());
    }
}
