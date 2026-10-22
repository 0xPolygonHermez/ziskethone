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

/// Per-message payload when the framed input is streamed over `PushJobInput`
/// (3 MiB, matching the ZisK SDK's `MAX_CHUNK_BYTES`; far under the 128 MiB
/// gRPC message cap).
const CHUNK_BYTES: usize = 3 * 1024 * 1024;

/// Largest framed input still sent as a single inline `InputChunk`. Above this
/// the input is streamed in `CHUNK_BYTES` pieces via `PushJobInput`, which
/// lifts the 128 MiB inline cap up to the zkVM input-region limit
/// (`MAX_INPUT_SIZE` = 2 GiB on the pre-develop-1.4.0-alpha coordinator).
/// A margin under the 128 MiB message cap leaves room for the 16-byte frame
/// header and the `ProveRequest` protobuf overhead.
const INLINE_MAX: usize = 100 * 1024 * 1024;

/// Split `framed` into `PushJobInputRequest`s of at most `CHUNK_BYTES` bytes
/// each, every one tagged with `job_id`. Owns its inputs so the iterator is
/// `'static` (streamable to `push_job_input`) and lazy (one chunk copy in
/// flight, never a second full copy of the input). Factored out so the
/// chunking math is unit-testable without a coordinator.
fn input_chunks(job_id: String, framed: prost::bytes::Bytes) -> impl Iterator<Item = grpc::PushJobInputRequest> {
    let mut off = 0usize;
    std::iter::from_fn(move || {
        if off >= framed.len() {
            return None;
        }
        let end = (off + CHUNK_BYTES).min(framed.len());
        let data = framed.slice(off..end).to_vec();
        off = end;
        Some(grpc::PushJobInputRequest {
            job_id: job_id.clone(),
            chunk: Some(grpc::InputChunk { data }),
        })
    })
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
    /// The guest's program VK from setup (4 u64 LE limbs), which the proof
    /// engine pins (`zisk-proof-engine --program-vk`).
    pub program_vk: Vec<u8>,
}

/// How long a `submit_when_free` spent sending the job vs. waiting for a free
/// worker. `send` is the accepted `job_request` RPC (the inline-input upload /
/// network time); `queue_wait` is the busy-retry time before it.
struct SubmitTiming {
    send: std::time::Duration,
    queue_wait: std::time::Duration,
    attempts: u32,
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
    ///
    /// The returned `SubmitTiming` splits the wall time into `send` (the one
    /// accepted `job_request` RPC — for an inline input this carries the whole
    /// input, so it is the upload / network time) and `queue_wait` (the
    /// busy-retry time spent before a worker was free, i.e. coordinator queue
    /// time, not network).
    async fn submit_when_free(
        &mut self,
        kind: grpc::job_kind::Kind,
        cancel: &CancellationToken,
    ) -> Result<Option<(String, SubmitTiming)>> {
        let t0 = std::time::Instant::now();
        let mut attempts = 0u32;
        loop {
            if cancel.is_cancelled() {
                return Ok(None);
            }
            let req = grpc::JobRequestMessage { job_kind: Some(grpc::JobKind { kind: Some(kind.clone()) }) };
            attempts += 1;
            let send_t = std::time::Instant::now();
            match self.client.job_request(req).await {
                Ok(r) => {
                    let send = send_t.elapsed();
                    let timing = SubmitTiming { send, queue_wait: t0.elapsed().saturating_sub(send), attempts };
                    return Ok(Some((r.into_inner().job_id, timing)));
                }
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
        // One framed blob (`[u64 LE len][data][pad]`), the same bytes whether
        // sent inline or streamed. Inputs up to `INLINE_MAX` ride in the
        // `ProveRequest` as a single inline chunk (today's path); larger ones
        // go as a `grpc://push` stream URI and are pushed in `CHUNK_BYTES`
        // pieces below, so the 128 MiB inline cap no longer bounds a block.
        let framed = frame_input(input);
        let input_bytes = framed.len();
        // `INLINE_MAX` by default; `ZISK_INLINE_MAX_BYTES` overrides it (e.g. 0
        // forces every input through the stream path — used to test streaming).
        let inline_max = std::env::var("ZISK_INLINE_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(INLINE_MAX);
        let (input_kind, to_stream) = if framed.len() <= inline_max {
            (grpc::input_kind::Kind::Inline(grpc::InputChunk { data: framed }), None)
        } else {
            (grpc::input_kind::Kind::StreamUri("grpc://push".into()), Some(framed))
        };
        let prove = grpc::job_kind::Kind::Prove(grpc::ProveRequest {
            hash_id: this.hash_id.clone(),
            input: Some(grpc::InputKind { kind: Some(input_kind) }),
            proof_timeout: None,
            proof_dest: grpc::ProofKind::Stark as i32,
            hints: None,
            // Let the coordinator draw its own proving seed (client seeds are
            // rejected unless it is configured to allow them). New in 1.4.0.
            random_seed: None,
        });
        let Some((job_id, submit)) = this.submit_when_free(prove, cancel).await? else {
            return Ok(Outcome::Cancelled);
        };
        // For an inline input the accepted `job_request` carried the whole
        // input, so `submit.send` is its upload/network time; `queue_wait` is
        // the time a worker was busy before accepting. (For a streamed input
        // `job_request` carried only the stream URI — the upload is timed in
        // `push_input` below.) These feed the proof-stats collector's network
        // breakdown.
        info!(
            %job_id,
            input_bytes,
            inline = to_stream.is_none(),
            send_ms = submit.send.as_millis() as u64,
            queue_wait_ms = submit.queue_wait.as_millis() as u64,
            submit_attempts = submit.attempts,
            "submitted proving job"
        );
        // The job is accepted only once a worker is assigned (`submit_when_free`
        // retries past "busy"), so the coordinator is ready for the pushed input.
        if let Some(framed) = to_stream {
            if this.push_input(&job_id, framed, cancel).await?.is_none() {
                info!(%job_id, "cancelled a newer block's proof while streaming its input");
                return Ok(Outcome::Cancelled);
            }
        }
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

    /// Push the framed input of an already-submitted `grpc://push` job in
    /// `CHUNK_BYTES` pieces over the client-streaming `PushJobInput` RPC,
    /// closing the stream to signal EOF. Cancellable like `wait()`: if a newer
    /// block supersedes this one mid-upload, `cancel` fires, the half-open
    /// stream is dropped and the job is `CancelJob`-ed to free the worker;
    /// returns `None` in that case, `Some(())` once all chunks are accepted.
    async fn push_input(&mut self, job_id: &str, framed: Vec<u8>, cancel: &CancellationToken) -> Result<Option<()>> {
        let framed = prost::bytes::Bytes::from(framed);
        let input_bytes = framed.len();
        let chunks = framed.len().div_ceil(CHUNK_BYTES);
        info!(%job_id, bytes = input_bytes, chunks, "streaming input");
        if framed.len() as u64 > grpc_zisk_max_input() {
            warn!(%job_id, bytes = framed.len(), "framed input exceeds the 2 GiB zkVM input cap; the coordinator may reject it");
        }
        // Lazily yield chunks (one `to_vec` copy in flight at a time, not a
        // second full copy of the input) tagged with `job_id`.
        let body = futures::stream::iter(input_chunks(job_id.to_string(), framed));
        let send_t = std::time::Instant::now();
        tokio::select! {
            r = self.client.push_job_input(body) => {
                r?;
                // Mirrors the inline log in `prove`: `send_ms` is the stream
                // upload / network time for the full input.
                info!(
                    %job_id,
                    input_bytes,
                    inline = false,
                    send_ms = send_t.elapsed().as_millis() as u64,
                    chunks,
                    "input streamed to coordinator"
                );
                Ok(Some(()))
            }
            _ = cancel.cancelled() => {
                let r = self.client.cancel_job(grpc::CancelJobRequest { job_id: job_id.to_string() }).await;
                match r {
                    Ok(r) => info!(job_id, cancelled = r.into_inner().cancelled, "cancelled proving job mid-upload"),
                    Err(e) => warn!(job_id, "CancelJob failed: {e}"),
                }
                Ok(None)
            }
        }
    }
}

/// The coordinator's zkVM input-region cap (`MAX_INPUT_SIZE`): 2 GiB on
/// pre-develop-1.4.0-alpha (`core/src/mem.rs` `MAX_INPUT_SIZE = 0x8000_0000`).
/// A soft client-side check only — the coordinator is the authority.
fn grpc_zisk_max_input() -> u64 {
    0x8000_0000
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

    /// The streamed chunks must reconstruct the framed input byte-for-byte,
    /// each stay within `CHUNK_BYTES`, and all carry the same `job_id`.
    #[test]
    fn chunking_reconstructs_framed_input() {
        for raw_len in [0usize, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, 3 * CHUNK_BYTES, 3 * CHUNK_BYTES + 7] {
            let input = vec![0xabu8; raw_len];
            let framed = frame_input(&input);
            let job = "job-123";
            let reqs: Vec<_> = input_chunks(job.to_string(), prost::bytes::Bytes::from(framed.clone())).collect();

            // At least one chunk (the server rejects an empty stream), and the
            // expected count.
            assert!(!reqs.is_empty());
            assert_eq!(reqs.len(), framed.len().div_ceil(CHUNK_BYTES).max(1));

            let mut rebuilt = Vec::new();
            for (i, r) in reqs.iter().enumerate() {
                assert_eq!(r.job_id, job);
                let data = &r.chunk.as_ref().unwrap().data;
                assert!(data.len() <= CHUNK_BYTES);
                // Every chunk but the last is exactly CHUNK_BYTES.
                if i + 1 < reqs.len() {
                    assert_eq!(data.len(), CHUNK_BYTES);
                }
                rebuilt.extend_from_slice(data);
            }
            assert_eq!(rebuilt, framed, "raw_len={raw_len}");
        }
    }

    /// Live end-to-end streaming prove against a real coordinator. Ignored by
    /// default; run with the coordinator + ELF + a RAW (unframed) ZEG0 input:
    ///   ZISK_COORDINATOR_URL=http://79.117.32.66:7000 \
    ///   TEST_ELF=/path/zisk_eth_guest.elf \
    ///   TEST_INPUT_RAW=/path/input.raw \
    ///   TEST_PROOF_OUT=/path/proof.bin \
    ///   cargo test --release prover::tests::stream_prove_live -- --ignored --nocapture
    /// A >128 MiB input exercises the `grpc://push` stream path. Prints the
    /// program VK so the proof can be checked with `zisk-proof-engine verify`.
    #[tokio::test]
    #[ignore]
    async fn stream_prove_live() -> Result<()> {
        let url = std::env::var("ZISK_COORDINATOR_URL").expect("ZISK_COORDINATOR_URL");
        let elf = std::env::var("TEST_ELF").expect("TEST_ELF");
        let raw = std::env::var("TEST_INPUT_RAW").expect("TEST_INPUT_RAW");
        let out = std::env::var("TEST_PROOF_OUT").unwrap_or_else(|_| "proof.bin".into());
        let prover = CoordinatorProver::connect(&url, std::path::Path::new(&elf)).await?;
        println!("PROGRAM_VK=0x{}", hex::encode(&prover.program_vk));
        let input = std::fs::read(&raw)?;
        println!("raw input {} bytes (framed {}; stream path at >{} MiB)", input.len(), input.len() + 16, INLINE_MAX >> 20);
        match prover.prove(&input, &CancellationToken::new()).await? {
            Outcome::Proved(p) => {
                std::fs::write(&out, &p.data)?;
                println!("PROVED proof_bytes={} written to {out}", p.data.len());
            }
            Outcome::Cancelled => panic!("unexpected cancellation"),
        }
        Ok(())
    }
}
