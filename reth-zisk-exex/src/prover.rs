//! Provers: a ZisK coordinator over gRPC (real proofs, cancellable), and
//! `ziskemu` (no proof, only the public output) for hosts without a GPU.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::ssz::{Root, MAX_PROOF_SIZE};

#[allow(clippy::all, dead_code)]
pub mod grpc {
    include!(concat!(env!("OUT_DIR"), "/zisk.coordinator.v1.rs"));
}
use grpc::zisk_coordinator_api_client::ZiskCoordinatorApiClient;

/// A finished proof. `data` is the `proof_data` that is signed and sent;
/// empty for the emulator.
pub struct Proof {
    pub data: Vec<u8>,
    /// The guest's public output, the `new_payload_request_root`, when the
    /// prover reports it (the emulator); a coordinator proof carries it
    /// inside `data`.
    pub root: Option<Root>,
}

impl Proof {
    /// Whether the proof's public output is `root`.
    pub fn commits_to(&self, root: &Root) -> bool {
        match &self.root {
            Some(r) => r == root,
            None => contains_publics(&self.data, root),
        }
    }
}

pub enum Outcome {
    Proved(Proof),
    Cancelled,
}

/// ZisK stdin framing: `[u64 LE len][data][zero pad to 8]` (`ZiskStdin::write_slice`).
pub fn frame_input(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 16);
    out.extend_from_slice(&(input.len() as u64).to_le_bytes());
    out.extend_from_slice(input);
    out.resize(out.len().next_multiple_of(8), 0);
    out
}

pub enum Prover {
    Coordinator(CoordinatorProver),
    Emulator(EmulatorProver),
}

impl Prover {
    pub async fn prove(&self, input: &[u8], cancel: &CancellationToken) -> Result<Outcome> {
        match self {
            Self::Coordinator(p) => p.prove(input, cancel).await,
            Self::Emulator(p) => p.prove(input, cancel).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

pub struct CoordinatorProver {
    client: ZiskCoordinatorApiClient<tonic::transport::Channel>,
    hash_id: String,
}

impl CoordinatorProver {
    /// Connect, register the guest ELF and run its setup (both idempotent on
    /// the coordinator side).
    pub async fn connect(url: &str, elf: &std::path::Path) -> Result<Self> {
        let channel = tonic::transport::Endpoint::from_shared(url.to_string())?
            .connect()
            .await
            .with_context(|| format!("connecting to the ZisK coordinator at {url}"))?;
        let mut client = ZiskCoordinatorApiClient::new(channel)
            .max_decoding_message_size(128 * 1024 * 1024)
            .max_encoding_message_size(128 * 1024 * 1024);

        let zisk_elf = std::fs::read(elf).with_context(|| format!("reading {}", elf.display()))?;
        let hash_id = client
            .register_guest_program(grpc::RegisterGuestProgramRequest { zisk_elf })
            .await?
            .into_inner()
            .hash_id;
        info!(%hash_id, elf = %elf.display(), "registered guest program");

        let mut this = Self { client, hash_id };
        let setup = grpc::job_kind::Kind::Setup(grpc::SetupRequest {
            hash_id: this.hash_id.clone(),
            with_hints: false,
            program_name: "zisk_eth_guest".into(),
            emulator_only: false,
        });
        let job_id = this.submit(setup).await?;
        match this.wait(&job_id, &CancellationToken::new()).await? {
            Some(grpc::job_kind_response::Kind::Setup(s)) => {
                info!(program_vk = %hex::encode(&s.vk), hash_mode = %s.hash_mode, "guest program set up");
            }
            other => bail!("setup job returned {other:?}"),
        }
        Ok(this)
    }

    async fn submit(&mut self, kind: grpc::job_kind::Kind) -> Result<String> {
        let req = grpc::JobRequestMessage { job_kind: Some(grpc::JobKind { kind: Some(kind) }) };
        Ok(self.client.job_request(req).await?.into_inner().job_id)
    }

    /// Long-poll `job_id` to a terminal state; on `cancel`, `CancelJob` it
    /// and return `None`.
    async fn wait(&mut self, job_id: &str, cancel: &CancellationToken) -> Result<Option<grpc::job_kind_response::Kind>> {
        use grpc::job_status::Status;
        loop {
            let req = grpc::WaitJobResultRequest { job_id: job_id.to_string(), timeout_seconds: Some(5) };
            let resp = tokio::select! {
                r = self.client.wait_job_result(req) => r?.into_inner(),
                _ = cancel.cancelled() => {
                    let r = self.client.cancel_job(grpc::CancelJobRequest { job_id: job_id.to_string() }).await;
                    match r {
                        Ok(r) => info!(job_id, cancelled = r.into_inner().cancelled, "cancelled proving job"),
                        Err(e) => warn!(job_id, "CancelJob failed: {e}"),
                    }
                    return Ok(None);
                }
            };
            match resp.job_status.and_then(|s| s.status) {
                Some(Status::Completed(_)) => {
                    return Ok(resp.result.and_then(|r| r.kind));
                }
                Some(Status::Failed(f)) => bail!("job {job_id} failed: {:?}", f.failure),
                Some(Status::Cancelled(_)) => return Ok(None),
                _ => {} // queued / running / waiting for input: poll again
            }
        }
    }

    async fn prove(&self, input: &[u8], cancel: &CancellationToken) -> Result<Outcome> {
        let mut this = Self { client: self.client.clone(), hash_id: self.hash_id.clone() };
        let prove = grpc::job_kind::Kind::Prove(grpc::ProveRequest {
            hash_id: this.hash_id.clone(),
            input: Some(grpc::InputKind {
                kind: Some(grpc::input_kind::Kind::Inline(grpc::InputChunk { data: frame_input(input) })),
            }),
            proof_timeout: None,
            proof_dest: grpc::ProofKind::Stark as i32,
            hints: None,
        });
        let job_id = this.submit(prove).await?;
        info!(%job_id, "submitted proving job");
        let t0 = std::time::Instant::now();
        let Some(result) = this.wait(&job_id, cancel).await? else {
            return Ok(Outcome::Cancelled);
        };
        let grpc::job_kind_response::Kind::Prove(resp) = result else {
            bail!("prove job {job_id} returned {result:?}");
        };
        let proof = resp.proof.context("prove response without a proof")?;
        info!(
            %job_id,
            bytes = proof.data.len(),
            steps = resp.stats.as_ref().map(|s| s.steps).unwrap_or(0),
            elapsed = ?t0.elapsed(),
            "proof ready"
        );
        if proof.data.len() > MAX_PROOF_SIZE {
            bail!("proof is {} bytes, over MAX_PROOF_SIZE", proof.data.len());
        }
        Ok(Outcome::Proved(Proof { data: proof.data, root: None }))
    }
}

/// Whether a serialized ZisK proof (`bincode` standard config of
/// `zisk_common::Proof`) carries `root` as its public output: the guest's 8
/// output words, one public each, appear in order as bincode varints. A
/// sanity check that the coordinator proved this input, not a verification.
pub fn contains_publics(proof: &[u8], root: &Root) -> bool {
    let mut needle = Vec::new();
    for w in root.chunks(4) {
        let v = u32::from_le_bytes(w.try_into().unwrap());
        match v {
            0..=250 => needle.push(v as u8),
            251..=0xffff => {
                needle.push(0xfb);
                needle.extend_from_slice(&(v as u16).to_le_bytes());
            }
            _ => {
                needle.push(0xfc);
                needle.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    proof.windows(needle.len()).any(|w| w == needle.as_slice())
}

// ---------------------------------------------------------------------------
// Emulator
// ---------------------------------------------------------------------------

pub struct EmulatorProver {
    pub ziskemu: PathBuf,
    pub elf: PathBuf,
    pub work_dir: PathBuf,
}

impl EmulatorProver {
    async fn prove(&self, input: &[u8], cancel: &CancellationToken) -> Result<Outcome> {
        std::fs::create_dir_all(&self.work_dir)?;
        let framed = self.work_dir.join("input.zisk.bin");
        let out = self.work_dir.join("ziskemu.out");
        std::fs::write(&framed, frame_input(input))?;
        let _ = std::fs::remove_file(&out);
        let mut child = tokio::process::Command::new(&self.ziskemu)
            .arg("-e")
            .arg(&self.elf)
            .arg("-i")
            .arg(&framed)
            .arg("-o")
            .arg(&out)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawning {}", self.ziskemu.display()))?;
        let t0 = std::time::Instant::now();
        let status = tokio::select! {
            s = child.wait() => s?,
            _ = cancel.cancelled() => {
                let _ = child.kill().await;
                return Ok(Outcome::Cancelled);
            }
        };
        if !status.success() {
            bail!("ziskemu exited with {status}");
        }
        let bytes = std::fs::read(&out).context("reading the ziskemu output")?;
        let root: Root = bytes.get(..32).context("ziskemu output shorter than 32 bytes")?.try_into()?;
        info!(elapsed = ?t0.elapsed(), root = %hex::encode(root), "ziskemu finished");
        Ok(Outcome::Proved(Proof { data: Vec::new(), root: Some(root) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing() {
        assert_eq!(frame_input(&[1, 2, 3]), [3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0]);
        assert_eq!(frame_input(&[0; 8]).len(), 16);
    }

    #[test]
    fn publics_search() {
        let mut root = [0u8; 32];
        root[..4].copy_from_slice(&7u32.to_le_bytes());
        root[4..8].copy_from_slice(&300u32.to_le_bytes());
        root[8..12].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        // [vk...] then the 8 publics as varints, then the remaining zeros.
        let mut proof = vec![0xfd, 1, 2, 3, 4, 5, 6, 7, 8];
        proof.extend_from_slice(&[7, 0xfb, 0x2c, 0x01, 0xfc, 0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0, 0]);
        assert!(contains_publics(&proof, &root));
        root[31] = 1;
        assert!(!contains_publics(&proof, &root));
    }
}
