//! EIP-8025 `ProofEngine.verify_execution_proof` for zisk_eth_guest proofs.
//!
//! The guest commits only the 32-byte `new_payload_request_root`, as 8 u32
//! little-endian words in publics 0..7 (`cpp-guest/include/zeg/zisk_io.hpp`,
//! `set_output_bytes32`). The other `PublicInput` fields are bound by the
//! configuration instead:
//! - `successful_validation` must be `true`: the guest halts on an invalid
//!   block, so it never proves a failed validation.
//! - `chain_id` must be the configured chain: the chain is a build-time
//!   constant of the ELF, which the pinned program VK identifies.
//! - `schema_id` must be `STATELESS_INPUT_SCHEMA_ID`.

use crate::proof::{self, VadcopKind};
use proofman_verifier::VadcopFinalProof;
use zisk_verifier::{GOLDILOCKS_ORDER, IS_VADCOP_FINAL_PROOF, PROGRAM_VK_LEN, ZISK_PUBLICS};

/// `STATELESS_INPUT_SCHEMA_ID` (consensus-specs eip8025 beacon-chain.md).
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// Number of publics the guest writes (the 32-byte root as u32 words).
const ROOT_WORDS: usize = 8;

/// A 32-byte verification key as 4 Goldilocks limbs (u64 little-endian bytes).
pub type Vk = [u64; PROGRAM_VK_LEN];

/// EIP-8025 `PublicInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInput {
    pub new_payload_request_root: [u8; 32],
    pub successful_validation: bool,
    pub chain_id: u64,
    pub schema_id: u16,
}

/// What a proof is checked against. The VKs are trusted inputs; the ones a
/// proof carries are not.
#[derive(Debug, Clone)]
pub struct Config {
    pub chain_id: u64,
    /// Accepted program VKs (one per guest ELF build).
    pub program_vks: Vec<Vk>,
    /// The vadcop_final setup VK of the proving key.
    pub setup_vk: Vk,
    /// Hash family of the proving key, e.g. `"blake3"`.
    pub hash: String,
}

/// Verify `proof_data` against `public_input`. `Err` carries the reason it is
/// invalid.
pub fn verify_execution_proof(proof_data: &[u8], public_input: &PublicInput, cfg: &Config) -> Result<(), String> {
    if !public_input.successful_validation {
        return Err("successful_validation is false; the guest only proves valid blocks".into());
    }
    if public_input.chain_id != cfg.chain_id {
        return Err(format!("chain_id {} is not the configured {}", public_input.chain_id, cfg.chain_id));
    }
    if public_input.schema_id != STATELESS_INPUT_SCHEMA_ID {
        return Err(format!("schema_id {:#06x} is not {STATELESS_INPUT_SCHEMA_ID:#06x}", public_input.schema_id));
    }

    let p = proof::decode(proof_data)?;
    if p.kind != VadcopKind::Final {
        return Err(format!("proof kind {:?}, only Final (a non-aggregated vadcop_final) is accepted", p.kind));
    }
    if p.hash != cfg.hash {
        return Err(format!("hash family {:?}, expected {:?}", p.hash, cfg.hash));
    }
    // The STARK's Fiat-Shamir transcript is over these publics, so they are
    // what the proof commits to; the stored program_vk copy is ignored.
    let publics = &p.publics_full;
    if publics.len() != PROGRAM_VK_LEN + ZISK_PUBLICS {
        return Err(format!("{} publics, expected {}", publics.len(), PROGRAM_VK_LEN + ZISK_PUBLICS));
    }
    if publics.iter().any(|&w| w >= GOLDILOCKS_ORDER) {
        return Err("non-canonical public".into());
    }
    let program_vk: Vk = publics[..PROGRAM_VK_LEN].try_into().unwrap();
    if !cfg.program_vks.contains(&program_vk) {
        return Err(format!("program VK {} is not pinned", vk_hex(&program_vk)));
    }
    let outputs = &publics[PROGRAM_VK_LEN..];
    if outputs.iter().any(|&w| w > u32::MAX as u64) {
        return Err("public output wider than 32 bits".into());
    }
    if outputs[ROOT_WORDS..].iter().any(|&w| w != 0) {
        return Err("public outputs past the root are not zero".into());
    }
    let root = root_of(outputs);
    if root != public_input.new_payload_request_root {
        return Err(format!(
            "proof commits new_payload_request_root 0x{}, not 0x{}",
            hex::encode(root),
            hex::encode(public_input.new_payload_request_root)
        ));
    }

    let expected = zisk_verifier::proof_size(&p.hash, false)
        .ok_or_else(|| format!("no vadcop_final verifier for hash family {:?}", p.hash))?;
    if !expected.admits(p.proof.len() * 8) {
        return Err(format!("STARK payload is {} bytes, expected {expected}", p.proof.len() * 8));
    }
    let mut stark_publics = Vec::with_capacity(1 + publics.len());
    stark_publics.push(IS_VADCOP_FINAL_PROOF);
    stark_publics.extend_from_slice(publics);
    let stark = VadcopFinalProof::new(p.proof, stark_publics, false, p.hash);
    // The generated verifier indexes into the proof; never let a malformed
    // one take the server down.
    let ok = std::panic::catch_unwind(|| zisk_verifier::verify_vadcop_final(&stark, &cfg.setup_vk))
        .map_err(|_| "STARK verifier panicked on this proof".to_string())?;
    if !ok {
        return Err("STARK proof does not verify".into());
    }
    Ok(())
}

/// The root from the guest's u32 output words.
pub fn root_of(outputs: &[u64]) -> [u8; 32] {
    let mut root = [0u8; 32];
    for (i, w) in outputs[..ROOT_WORDS].iter().enumerate() {
        root[4 * i..4 * i + 4].copy_from_slice(&(*w as u32).to_le_bytes());
    }
    root
}

/// 32-byte VK from hex (`0x` optional), as 4 u64 little-endian limbs: the
/// byte layout of the coordinator's `SetupResponse.vk`.
pub fn parse_vk_hex(s: &str) -> Result<Vk, String> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| format!("bad VK hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("VK is {} bytes, expected 32", bytes.len()));
    }
    let vk: Vk = std::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()));
    if vk.iter().any(|&w| w >= GOLDILOCKS_ORDER) {
        return Err("VK has a non-canonical limb".into());
    }
    Ok(vk)
}

/// A `<proving key>/.../vadcop_final.verkey.json`: a JSON array of 4 limbs,
/// numbers or decimal strings.
pub fn parse_verkey_json(s: &str) -> Result<Vk, String> {
    let v: Vec<serde_json::Value> = serde_json::from_str(s).map_err(|e| format!("bad verkey JSON: {e}"))?;
    if v.len() != PROGRAM_VK_LEN {
        return Err(format!("verkey has {} limbs, expected {PROGRAM_VK_LEN}", v.len()));
    }
    let mut vk = [0u64; PROGRAM_VK_LEN];
    for (i, e) in v.iter().enumerate() {
        vk[i] = match e {
            serde_json::Value::Number(n) => n.as_u64(),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        }
        .ok_or_else(|| format!("verkey limb {i} is not a u64"))?;
        if vk[i] >= GOLDILOCKS_ORDER {
            return Err(format!("verkey limb {i} is non-canonical"));
        }
    }
    Ok(vk)
}

pub fn vk_hex(vk: &[u64]) -> String {
    format!("0x{}", hex::encode(vk.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::tests::{encode, KindOut};

    const VK: Vk = [11, 22, 33, 44];

    fn cfg() -> Config {
        Config { chain_id: 11155111, program_vks: vec![VK], setup_vk: [1, 2, 3, 4], hash: "blake3".into() }
    }

    fn root() -> [u8; 32] {
        std::array::from_fn(|i| i as u8 + 1)
    }

    fn input() -> PublicInput {
        PublicInput { new_payload_request_root: root(), successful_validation: true, chain_id: 11155111, schema_id: 0x1501 }
    }

    fn publics(vk: Vk, root: [u8; 32]) -> Vec<u64> {
        let mut p = vk.to_vec();
        for i in 0..8 {
            p.push(u32::from_le_bytes(root[4 * i..4 * i + 4].try_into().unwrap()) as u64);
        }
        p.resize(68, 0);
        p
    }

    fn stark_len() -> usize {
        zisk_verifier::proof_size("blake3", false).unwrap().max_bytes() / 8
    }

    fn proof(vk: Vk, root: [u8; 32]) -> Vec<u8> {
        encode(vec![0; stark_len()], KindOut::Final, publics(vk, root))
    }

    fn err(data: &[u8], pi: &PublicInput) -> String {
        verify_execution_proof(data, pi, &cfg()).unwrap_err()
    }

    #[test]
    fn root_words_match_guest_layout() {
        let p = publics(VK, root());
        assert_eq!(p[4], 0x04030201);
        assert_eq!(root_of(&p[4..]), root());
    }

    #[test]
    fn public_input_fields() {
        let data = proof(VK, root());
        assert!(err(&data, &PublicInput { successful_validation: false, ..input() }).contains("successful_validation"));
        assert!(err(&data, &PublicInput { chain_id: 1, ..input() }).contains("chain_id"));
        assert!(err(&data, &PublicInput { schema_id: 0, ..input() }).contains("schema_id"));
    }

    #[test]
    fn binds_root_and_program_vk() {
        let mut other = root();
        other[31] ^= 1;
        assert!(err(&proof(VK, root()), &PublicInput { new_payload_request_root: other, ..input() })
            .contains("new_payload_request_root"));
        assert!(err(&proof([5, 6, 7, 8], root()), &input()).contains("not pinned"));
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut p = publics(VK, root());
        p[20] = 1;
        assert!(err(&encode(vec![0; stark_len()], KindOut::Final, p), &input()).contains("past the root"));
        let mut p = publics(VK, root());
        p[5] = 1 << 32;
        assert!(err(&encode(vec![0; stark_len()], KindOut::Final, p), &input()).contains("32 bits"));
        assert!(err(&encode(vec![0; stark_len()], KindOut::Recurser, publics(VK, root())), &input()).contains("kind"));
        assert!(err(&encode(vec![0; 3], KindOut::Final, publics(VK, root())), &input()).contains("STARK payload"));
        let mut data = proof(VK, root());
        data.push(0);
        assert!(err(&data, &input()).contains("trailing"));
    }

    #[test]
    fn garbage_stark_does_not_verify() {
        assert_eq!(err(&proof(VK, root()), &input()), "STARK proof does not verify");
    }

    #[test]
    fn vk_parsing() {
        let hex = vk_hex(&VK);
        assert_eq!(parse_vk_hex(&hex).unwrap(), VK);
        assert!(parse_vk_hex("0x00").is_err());
        assert_eq!(parse_verkey_json(r#"[11, "22", 33, "44"]"#).unwrap(), VK);
        assert!(parse_verkey_json("[1,2,3]").is_err());
    }
}
