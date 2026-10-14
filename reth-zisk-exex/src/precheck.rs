//! Native pre-check of an input before it goes to the prover: the host
//! build of the guest (`cpp-guest/build/zisk_eth_guest`) recomputes the
//! block hash (line 1) and the `new_payload_request_root` (line 2, the
//! public output the proof will carry). Run as a subprocess: a guest fatal
//! is `abort()`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::ssz::Root;

pub struct Precheck {
    pub guest_host: PathBuf,
}

fn parse_root(line: &str) -> Result<Root> {
    let b = hex::decode(line.trim().trim_start_matches("0x")).with_context(|| format!("bad hex {line:?}"))?;
    b.try_into().map_err(|_| anyhow::anyhow!("not 32 bytes: {line:?}"))
}

impl Precheck {
    /// The `new_payload_request_root` of `input`, after checking the guest
    /// recomputes `block_hash`.
    pub async fn run(&self, input: &Path, block_hash: &Root) -> Result<Root> {
        // RLIMIT_CORE = 1 byte keeps a guest abort() from going through
        // apport, which costs ~8 s per crash.
        let out = tokio::time::timeout(
            Duration::from_secs(120),
            tokio::process::Command::new("prlimit")
                .arg("--core=1")
                .arg(&self.guest_host)
                .arg(input)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("host guest timed out")?
        .with_context(|| format!("running {}", self.guest_host.display()))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let fatal = stderr.lines().find(|l| l.starts_with("guest: ")).unwrap_or("");
            bail!("host guest rejected the block ({}) {fatal}", out.status);
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with("0x")).collect();
        let [hash, root] = lines.as_slice() else {
            bail!("host guest printed {} hash lines, expected 2", lines.len());
        };
        if parse_root(hash)? != *block_hash {
            bail!("host guest computed block hash {hash}, expected 0x{}", hex::encode(block_hash));
        }
        parse_root(root)
    }
}
