//! `zisk-proof-engine`: the EIP-8025 proof engine for the beacon node
//! (Lighthouse `--proof-engine-endpoint`). It implements
//! `ProofEngine.verify_execution_proof` for ZisK VadcopFinal proofs of the
//! zisk_eth_guest, the proofs reth-zisk-exex produces and signs.

mod api;
mod proof;
mod verify;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use verify::{parse_verkey_json, parse_vk_hex, vk_hex, Config, PublicInput, Vk, STATELESS_INPUT_SCHEMA_ID};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the proof-engine HTTP API.
    Serve {
        #[arg(long, default_value = "127.0.0.1:9551")]
        listen: SocketAddr,
        /// The EIP-8025 proof type served (the exex's `--zisk.proof-type`).
        #[arg(long)]
        proof_type: u8,
        #[command(flatten)]
        keys: KeyArgs,
    },
    /// Verify one proof file offline, as the server would.
    Verify {
        /// `proof_data` (the exex's `proof.bin`).
        proof: PathBuf,
        /// The expected new_payload_request_root (0x-hex).
        #[arg(long)]
        root: String,
        #[command(flatten)]
        keys: KeyArgs,
    },
    /// Print what a proof claims (VKs, kind, committed root). UNTRUSTED: the
    /// proof is not verified. Use it to bootstrap the pinned VKs from a proof
    /// you produced yourself.
    Inspect { proof: PathBuf },
}

#[derive(Args)]
struct KeyArgs {
    /// Chain id the guest ELF was built for (1 mainnet, 11155111 Sepolia).
    #[arg(long)]
    chain_id: u64,
    /// Accepted program VK (32-byte hex, the exex's logged `program_vk`).
    /// Repeat to accept several guest builds.
    #[arg(long = "program-vk", required = true)]
    program_vks: Vec<String>,
    /// vadcop_final setup VK of the proving key: 32-byte hex, or the path of
    /// `<proving key>/zisk/vadcop_final/vadcop_final.verkey.json`.
    #[arg(long)]
    setup_vk: String,
    /// Hash family of the proving key.
    #[arg(long, default_value = "blake3")]
    hash: String,
}

impl KeyArgs {
    fn config(&self) -> Result<Config> {
        let program_vks = self
            .program_vks
            .iter()
            .map(|s| parse_vk_hex(s).map_err(anyhow::Error::msg).with_context(|| format!("--program-vk {s}")))
            .collect::<Result<Vec<Vk>>>()?;
        let setup_vk = if std::path::Path::new(&self.setup_vk).is_file() {
            let s = std::fs::read_to_string(&self.setup_vk).with_context(|| format!("reading {}", self.setup_vk))?;
            parse_verkey_json(&s).map_err(anyhow::Error::msg).with_context(|| self.setup_vk.clone())?
        } else {
            parse_vk_hex(&self.setup_vk).map_err(anyhow::Error::msg).context("--setup-vk")?
        };
        if zisk_verifier::expected_proof_bytes(&self.hash, false).is_none() {
            bail!("no vadcop_final verifier for hash family {:?}", self.hash);
        }
        Ok(Config { chain_id: self.chain_id, program_vks, setup_vk, hash: self.hash.clone() })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Serve { listen, proof_type, keys } => {
            let cfg = keys.config()?;
            info!(
                %listen,
                proof_type,
                chain_id = cfg.chain_id,
                program_vks = ?cfg.program_vks.iter().map(|v| vk_hex(v)).collect::<Vec<_>>(),
                setup_vk = %vk_hex(&cfg.setup_vk),
                hash = cfg.hash,
                "proof engine listening"
            );
            let app = api::router(Arc::new(api::Engine { cfg, proof_type }));
            let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("bind {listen}"))?;
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Cmd::Verify { proof, root, keys } => {
            let cfg = keys.config()?;
            let data = std::fs::read(&proof).with_context(|| format!("reading {}", proof.display()))?;
            let root: [u8; 32] = hex::decode(root.trim_start_matches("0x"))
                .ok()
                .and_then(|b| b.try_into().ok())
                .context("--root: expected 32 hex bytes")?;
            let pi = PublicInput {
                new_payload_request_root: root,
                successful_validation: true,
                chain_id: cfg.chain_id,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            };
            let t0 = std::time::Instant::now();
            match verify::verify_execution_proof(&data, &pi, &cfg) {
                Ok(()) => println!("VALID ({:?})", t0.elapsed()),
                Err(reason) => {
                    println!("INVALID: {reason}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Inspect { proof } => {
            let data = std::fs::read(&proof).with_context(|| format!("reading {}", proof.display()))?;
            let p = proof::decode(&data).map_err(anyhow::Error::msg)?;
            println!("UNTRUSTED: decoded, not verified");
            println!("bytes            {}", data.len());
            println!("kind             {:?}", p.kind);
            println!("hash             {} (program vk {:?})", p.hash, p.stored_program_vk.hash_mode);
            println!("stark words      {}", p.proof.len());
            println!("setup vk (claim) {}", vk_hex(&p.zisk_vk));
            if p.publics_full.len() >= 4 + 8 {
                println!("program vk       {}", vk_hex(&p.publics_full[..4]));
                if p.stored_program_vk.vk != p.publics_full[..4] {
                    println!("  (stored program_vk differs: {})", vk_hex(&p.stored_program_vk.vk));
                }
                println!("output root      0x{}", hex::encode(verify::root_of(&p.publics_full[4..])));
            } else {
                println!("publics          {} words (malformed)", p.publics_full.len());
            }
        }
    }
    Ok(())
}
