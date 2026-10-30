//! The build stamp the guest ELF carries (`ZEG_BUILD_FLAGS:` in `.rodata`,
//! written by `cpp-guest/zisk/CMakeLists.txt`): how the ELF was configured.
//! Prove mode refuses an ELF whose stamp is missing or says it is not a
//! deployable build for this chain (audit H8).

use std::collections::BTreeMap;

use anyhow::{bail, Result};

const MARKER: &[u8] = b"ZEG_BUILD_FLAGS:";

/// The stamp as `key=value` pairs, or `None` if the ELF has none (built
/// before the stamp existed).
pub fn read(elf: &[u8]) -> Option<BTreeMap<String, String>> {
    let start = elf.windows(MARKER.len()).position(|w| w == MARKER)? + MARKER.len();
    let len = elf[start..].iter().position(|&b| b == 0)?;
    let text = std::str::from_utf8(&elf[start..start + len]).ok()?;
    Some(
        text.split(';')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

/// Fails unless the stamp describes a deployable build for `chain_id`: the
/// fork from the compile-time schedule, the EIP-8025 output, no debug
/// output, and the chain the node runs.
pub fn check_deployable(flags: &BTreeMap<String, String>, chain_id: u64) -> Result<()> {
    let chain = match chain_id {
        1 => "mainnet",
        11155111 => "sepolia",
        other => bail!("no guest chain for chain id {other}"),
    };
    let want = [
        ("chain", chain),
        ("fork_from_input", "0"),
        ("output", "npr"),
        ("heap_stats", "0"),
        ("build_type", "Release"),
    ];
    for (key, value) in want {
        match flags.get(key) {
            Some(v) if v == value => {}
            got => bail!("guest ELF built with {key}={}, need {value}", got.map_or("<missing>", |v| v)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_with(stamp: &str) -> Vec<u8> {
        let mut elf = b"\x7fELF...".to_vec();
        elf.extend_from_slice(MARKER);
        elf.extend_from_slice(stamp.as_bytes());
        elf.extend_from_slice(b"\0rest");
        elf
    }

    const SEPOLIA: &str = "chain=sepolia;backend=evmone;fork_from_input=0;output=npr;heap_stats=0;\
        jumpdest_sw=0;bswap_builtin=1;zisk_dma=0;analysis_cache_slots=1152;build_type=Release";

    #[test]
    fn deploy_stamp_passes() {
        let flags = read(&elf_with(SEPOLIA)).unwrap();
        assert_eq!(flags["backend"], "evmone");
        check_deployable(&flags, 11155111).unwrap();
    }

    #[test]
    fn wrong_chain_or_test_build_fails() {
        let flags = read(&elf_with(SEPOLIA)).unwrap();
        assert!(check_deployable(&flags, 1).is_err());
        let test = SEPOLIA.replace("fork_from_input=0", "fork_from_input=1");
        assert!(check_deployable(&read(&elf_with(&test)).unwrap(), 11155111).is_err());
    }

    #[test]
    fn no_stamp() {
        assert!(read(b"\x7fELF no stamp here").is_none());
    }
}
