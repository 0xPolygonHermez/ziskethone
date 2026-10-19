//! Provers: a ZisK coordinator over gRPC (real proofs), and
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
    /// inside `data`, checked by the beacon node's proof engine.
    pub root: Option<Root>,
}


/// How long a proving job is retried while the cluster is busy.
const BUSY_RETRY: std::time::Duration = std::time::Duration::from_secs(20);

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
    /// The guest's program VK from setup (4 u64 LE limbs), which the proof
    /// engine pins (`zisk-proof-engine --program-vk`).
    pub program_vk: Vec<u8>,
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

        let mut this = Self { client, hash_id, program_vk: Vec::new() };
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
                this.program_vk = s.vk;
            }
            other => bail!("setup job returned {other:?}"),
        }
        Ok(this)
    }

    async fn submit(&mut self, kind: grpc::job_kind::Kind) -> Result<String> {
        let req = grpc::JobRequestMessage { job_kind: Some(grpc::JobKind { kind: Some(kind) }) };
        Ok(self.client.job_request(req).await?.into_inner().job_id)
    }

    /// `submit`, retried while the cluster is busy with the previous block's
    /// proof: it runs one job at a time and refuses the next one with
    /// "workers are busy running another job" instead of queueing it. When a
    /// newer block arrives the previous proof is being `CancelJob`-ed
    /// concurrently, so the worker frees within a poll or two. Returns `None`
    /// if `cancel` fires before the job is accepted (this block, in turn, was
    /// superseded while waiting for the worker).
    async fn submit_when_free(&mut self, kind: grpc::job_kind::Kind, cancel: &CancellationToken) -> Result<Option<String>> {
        let t0 = std::time::Instant::now();
        loop {
            if cancel.is_cancelled() {
                return Ok(None);
            }
            let req = grpc::JobRequestMessage { job_kind: Some(grpc::JobKind { kind: Some(kind.clone()) }) };
            match self.client.job_request(req).await {
                Ok(r) => return Ok(Some(r.into_inner().job_id)),
                Err(e) if e.code() == tonic::Code::Unavailable
                    && e.message().contains("busy running another job")
                    && t0.elapsed() < BUSY_RETRY =>
                {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
                        _ = cancel.cancelled() => return Ok(None),
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Long-poll `job_id` to a terminal state; on `cancel`, `CancelJob` it
    /// and return `None`. A running proof is cancelled this way when a newer
    /// block supersedes it — the 1.4.0 coordinator frees its worker on
    /// `CancelJob` (under v1.3.2-alpha this wedged the workers "setting up"
    /// for ~10 min, which is why submitted proofs used to run to completion).
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

    /// Prove `input`, cancellable right through to completion: when a newer
    /// block supersedes this one, `cancel` fires and we `CancelJob` the
    /// running proof so the coordinator's single worker is freed for the new
    /// block. (Under v1.3.2-alpha, 2026-10-15, `CancelJob` on a running proof
    /// wedged the workers for ~10 min, so proofs were then left to finish;
    /// the 1.4.0 coordinator cancels cleanly, so that rule is lifted.)
    async fn prove(&self, input: &[u8], cancel: &CancellationToken) -> Result<Outcome> {
        let mut this = Self { client: self.client.clone(), hash_id: self.hash_id.clone(), program_vk: Vec::new() };
        let prove = grpc::job_kind::Kind::Prove(grpc::ProveRequest {
            hash_id: this.hash_id.clone(),
            input: Some(grpc::InputKind {
                kind: Some(grpc::input_kind::Kind::Inline(grpc::InputChunk { data: frame_input(input) })),
            }),
            proof_timeout: None,
            proof_dest: grpc::ProofKind::Stark as i32,
            hints: None,
            // Let the coordinator draw its own proving seed (client seeds are
            // rejected unless it is configured to allow them). New in 1.4.0.
            random_seed: None,
        });
        let Some(job_id) = this.submit_when_free(prove, cancel).await? else {
            return Ok(Outcome::Cancelled);
        };
        info!(%job_id, "submitted proving job");
        let t0 = std::time::Instant::now();
        let Some(result) = this.wait(&job_id, cancel).await? else {
            info!(%job_id, "cancelled the in-flight proof for a newer block");
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

}
