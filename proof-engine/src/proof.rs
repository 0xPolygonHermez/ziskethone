//! The `proof_data` wire format: the bincode (standard config) encoding of
//! `zisk_common::Proof`, as the ZisK coordinator returns it in
//! `ProveResponse.proof.data` and reth-zisk-exex signs it.
//!
//! Only the Vadcop body is mirrored. Field order and variant order are the
//! encoding, so they are copied verbatim from ZisK v1.3.2-alpha
//! `common/src/proof.rs` and `common/src/hash_mode.rs`. Depending on
//! `zisk-common` itself would pull the whole prover.

use serde::Deserialize;

/// EIP-8025 `MAX_PROOF_SIZE`.
pub const MAX_PROOF_SIZE: usize = 4 * 1024 * 1024;

/// `zisk_common::VadcopKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum VadcopKind {
    /// Raw vadcop_final leaf; STARK publics `[flag=1 | vk(4) | inputs(64)]`.
    Final,
    /// Aggregated (recurser) proof; flag = 0.
    Recurser,
    /// Compressed proof; no flag.
    Minimal,
}

/// `zisk_common::HashMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum HashMode {
    Poseidon1,
    Poseidon2,
    Blake3,
}

/// `zisk_common::ProofBody`, Vadcop variant only (variant 0). A Plonk body
/// (variant 1) fails to decode.
#[derive(Debug, Clone, Deserialize)]
pub enum ProofBody {
    Vadcop {
        /// The STARK payload, without publics.
        proof: Vec<u64>,
        /// The setup (vadcop_final) verification key the prover claims. Untrusted.
        zisk_vk: Vec<u64>,
        kind: VadcopKind,
        /// Hash family id, e.g. `"blake3"`.
        hash: String,
        /// Flag-free STARK publics `[program_vk(4) | inputs(64)]`.
        publics_full: Vec<u64>,
    },
}

/// `zisk_common::ProgramVK`. A stored copy; verification reads the VK from
/// the publics the STARK commits to instead.
#[derive(Debug, Clone, Deserialize)]
pub struct ProgramVk {
    pub vk: Vec<u64>,
    pub hash_mode: HashMode,
}

/// `zisk_common::Proof`.
#[derive(Debug, Clone, Deserialize)]
pub struct Proof {
    pub body: ProofBody,
    pub program_vk: ProgramVk,
}

/// A decoded Vadcop proof.
#[derive(Debug, Clone)]
pub struct VadcopProof {
    pub proof: Vec<u64>,
    pub zisk_vk: Vec<u64>,
    pub kind: VadcopKind,
    pub hash: String,
    pub publics_full: Vec<u64>,
    pub stored_program_vk: ProgramVk,
}

/// Decode `proof_data`. The whole input must be consumed.
pub fn decode(data: &[u8]) -> Result<VadcopProof, String> {
    if data.is_empty() {
        return Err("empty proof_data".into());
    }
    if data.len() > MAX_PROOF_SIZE {
        return Err(format!("proof_data is {} bytes, over MAX_PROOF_SIZE", data.len()));
    }
    // The body's variant index is the first varint byte.
    if data[0] == 1 {
        return Err("Plonk proofs are not supported, only VadcopFinal".into());
    }
    let config = bincode::config::standard().with_limit::<{ 2 * MAX_PROOF_SIZE }>();
    let (proof, used): (Proof, usize) = bincode::serde::decode_from_slice(data, config)
        .map_err(|e| format!("cannot decode proof_data: {e}"))?;
    if used != data.len() {
        return Err(format!("{} trailing bytes after the proof", data.len() - used));
    }
    let ProofBody::Vadcop { proof: stark, zisk_vk, kind, hash, publics_full } = proof.body;
    Ok(VadcopProof { proof: stark, zisk_vk, kind, hash, publics_full, stored_program_vk: proof.program_vk })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde::Serialize;

    // Encoding-side twins of the mirrored types, for building test proofs.
    #[derive(Serialize)]
    pub enum KindOut {
        Final,
        Recurser,
        #[allow(dead_code)]
        Minimal,
    }
    #[derive(Serialize)]
    enum HashOut {
        #[allow(dead_code)]
        Poseidon1,
        #[allow(dead_code)]
        Poseidon2,
        Blake3,
    }
    #[derive(Serialize)]
    enum BodyOut {
        Vadcop { proof: Vec<u64>, zisk_vk: Vec<u64>, kind: KindOut, hash: String, publics_full: Vec<u64> },
        #[allow(dead_code)]
        Plonk { proof_bytes: Vec<u8> },
    }
    #[derive(Serialize)]
    struct VkOut {
        vk: Vec<u64>,
        hash_mode: HashOut,
    }
    #[derive(Serialize)]
    struct ProofOut {
        body: BodyOut,
        program_vk: VkOut,
    }

    pub fn encode(proof: Vec<u64>, kind: KindOut, publics_full: Vec<u64>) -> Vec<u8> {
        let vk = publics_full[..4].to_vec();
        let p = ProofOut {
            body: BodyOut::Vadcop { proof, zisk_vk: vec![9; 4], kind, hash: "blake3".into(), publics_full },
            program_vk: VkOut { vk, hash_mode: HashOut::Blake3 },
        };
        bincode::serde::encode_to_vec(&p, bincode::config::standard()).unwrap()
    }

    #[test]
    fn roundtrip() {
        let publics: Vec<u64> = (0..68).collect();
        let bytes = encode(vec![1, 2, 3], KindOut::Final, publics.clone());
        let p = decode(&bytes).unwrap();
        assert_eq!(p.proof, vec![1, 2, 3]);
        assert_eq!(p.zisk_vk, vec![9; 4]);
        assert_eq!(p.kind, VadcopKind::Final);
        assert_eq!(p.hash, "blake3");
        assert_eq!(p.publics_full, publics);
        assert_eq!(p.stored_program_vk.hash_mode, HashMode::Blake3);
    }

    #[test]
    fn rejects_trailing_bytes_and_plonk() {
        let mut bytes = encode(vec![1], KindOut::Final, vec![0; 68]);
        bytes.push(0);
        assert!(decode(&bytes).unwrap_err().contains("trailing"));
        let plonk = ProofOut {
            body: BodyOut::Plonk { proof_bytes: vec![1] },
            program_vk: VkOut { vk: vec![0; 4], hash_mode: HashOut::Blake3 },
        };
        let bytes = bincode::serde::encode_to_vec(&plonk, bincode::config::standard()).unwrap();
        assert!(decode(&bytes).unwrap_err().contains("Plonk"));
        assert!(decode(&[]).is_err());
        assert!(decode(&[0, 200]).is_err());
    }
}
