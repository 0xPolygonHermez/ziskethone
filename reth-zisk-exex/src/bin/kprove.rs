//! `kprove` — batch coordinator-prove driver for the killer-block sweep.
//!
//! Reuses the exex's streaming `CoordinatorProver` (same code path the live
//! prover uses: inline `InputChunk` up to `INLINE_MAX`, else a `grpc://push`
//! stream in `CHUNK_BYTES` pieces, lifting the 128 MiB inline cap to the 2 GiB
//! zkVM input region). Connects once (register + setup), then proves a list of
//! RAW ZEG0 input files, timing each, retrying with a recovery wait, and
//! appending a CSV row per block. Not part of the production `reth-zisk` bin.
//!
//!   kprove --coordinator http://HOST:7000 --elf guest.elf \
//!          --list inputs.txt --csv results.csv \
//!          [--timeout 1800] [--retries 4] [--recover 60] [--resume]
//!
//! `inputs.txt`: one raw input file path per line (blank/`#` lines ignored).
//! CSV columns: name,status,wall_ms,proof_bytes,attempts,error

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

// Minimal stand-ins for the two `crate::ssz` items `prover.rs` needs, so this
// bin pulls in `prover.rs` without the rest of the exex (no reth, no sha2).
mod ssz {
    pub type Root = [u8; 32];
    pub const MAX_PROOF_SIZE: usize = 4_194_304;
}
#[path = "../prover.rs"]
mod prover;

use prover::{CoordinatorProver, Outcome, Prover};

/// Connect (register + setup) and return the pub `Prover` wrapper plus the
/// program VK, so we call the public `Prover::prove`.
async fn connect(url: &str, elf: &std::path::Path) -> Result<(Prover, Vec<u8>)> {
    let cp = CoordinatorProver::connect(url, elf).await?;
    let vk = cp.program_vk.clone();
    Ok((Prover::Coordinator(cp), vk))
}

#[derive(clap::Parser)]
#[command(about = "Batch coordinator-prove driver (killer-block sweep)")]
struct Args {
    #[arg(long)]
    coordinator: String,
    #[arg(long)]
    elf: PathBuf,
    /// File listing raw ZEG0 input paths, one per line.
    #[arg(long)]
    list: PathBuf,
    /// CSV output (appended; rows flushed per block).
    #[arg(long)]
    csv: PathBuf,
    /// Per-attempt wall timeout, seconds.
    #[arg(long, default_value_t = 1800)]
    timeout: u64,
    /// Attempts per block before giving up.
    #[arg(long, default_value_t = 4)]
    retries: u32,
    /// Wait after a failed attempt (coordinator worker-down recovery window), seconds.
    #[arg(long, default_value_t = 60)]
    recover: u64,
    /// Skip inputs already recorded OK in the CSV (resume a partial run).
    #[arg(long, default_value_t = false)]
    resume: bool,
}

fn name_of(p: &std::path::Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = <Args as clap::Parser>::parse();

    // Input list.
    let inputs: Vec<PathBuf> = std::fs::read_to_string(&args.list)
        .with_context(|| format!("reading {}", args.list.display()))?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(PathBuf::from)
        .collect();

    // Resume set: names already OK.
    let mut done = std::collections::HashSet::new();
    if args.resume {
        if let Ok(f) = std::fs::File::open(&args.csv) {
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                let mut it = line.splitn(3, ',');
                let (name, status) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
                if status == "OK" {
                    done.insert(name.to_string());
                }
            }
        }
    }

    let new_csv = !args.csv.exists() || std::fs::metadata(&args.csv).map(|m| m.len() == 0).unwrap_or(true);
    let mut csv = std::fs::OpenOptions::new().create(true).append(true).open(&args.csv)?;
    if new_csv {
        writeln!(csv, "name,status,wall_ms,proof_bytes,attempts,error")?;
        csv.flush()?;
    }

    eprintln!("[kprove] connecting + setup: {} ({})", args.coordinator, args.elf.display());
    let (mut prover, vk) = connect(&args.coordinator, &args.elf).await?;
    eprintln!("[kprove] program_vk=0x{}", hex::encode(&vk));

    let total = inputs.len();
    let mut ok = 0usize;
    let mut failed = 0usize;
    for (i, path) in inputs.iter().enumerate() {
        let name = name_of(path);
        if done.contains(&name) {
            eprintln!("[kprove] ({}/{}) skip (done): {name}", i + 1, total);
            continue;
        }
        let raw = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                writeln!(csv, "{name},READ_FAIL,0,0,0,{}", e.to_string().replace([',', '\n'], ";"))?;
                csv.flush()?;
                failed += 1;
                continue;
            }
        };
        let sz = raw.len();
        eprintln!("[kprove] ({}/{}) proving {name} (raw {} MiB) ...", i + 1, total, sz / (1024 * 1024));

        let mut last_err = String::new();
        let mut rec: Option<(u128, usize)> = None; // (wall_ms, proof_bytes)
        let mut used = 0u32;
        for attempt in 1..=args.retries {
            used = attempt;
            let t0 = Instant::now();
            let cancel = CancellationToken::new();
            let fut = prover.prove(&raw, &cancel);
            let res = tokio::time::timeout(Duration::from_secs(args.timeout), fut).await;
            let ms = t0.elapsed().as_millis();
            match res {
                Ok(Ok(Outcome::Proved(p))) => {
                    rec = Some((ms, p.data.len()));
                    break;
                }
                Ok(Ok(Outcome::Cancelled)) => {
                    last_err = "cancelled".into();
                }
                Ok(Err(e)) => {
                    last_err = format!("{e:#}");
                }
                Err(_) => {
                    last_err = format!("attempt timeout after {}s", args.timeout);
                }
            }
            eprintln!("[kprove]   attempt {attempt}/{} failed in {ms}ms: {last_err}", args.retries);
            if attempt < args.retries {
                tokio::time::sleep(Duration::from_secs(args.recover)).await;
                // Every second failed attempt, re-connect (re-setup) in case a
                // worker crash wiped the active ASM program on the coordinator.
                if attempt % 2 == 0 {
                    eprintln!("[kprove]   re-connecting (re-setup) after repeated failures ...");
                    match connect(&args.coordinator, &args.elf).await {
                        Ok((p, _)) => prover = p,
                        Err(e) => eprintln!("[kprove]   re-connect failed: {e:#}"),
                    }
                }
            }
        }

        match rec {
            Some((ms, bytes)) => {
                writeln!(csv, "{name},OK,{ms},{bytes},{used},")?;
                ok += 1;
                eprintln!("[kprove]   OK {ms}ms {bytes} bytes");
            }
            None => {
                writeln!(csv, "{name},FAILED,0,0,{used},{}", last_err.replace([',', '\n'], ";"))?;
                failed += 1;
                eprintln!("[kprove]   FAILED after {used} attempts: {last_err}");
            }
        }
        csv.flush()?;
    }

    eprintln!("[kprove] DONE: {ok} OK, {failed} FAILED, {} total", total);
    Ok(())
}
