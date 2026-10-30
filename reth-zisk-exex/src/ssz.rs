//! The few EIP-8025 consensus containers the ExEx signs and submits, with
//! their SSZ serialization and `hash_tree_root` (consensus-specs master,
//! `specs/_features/eip8025/beacon-chain.md`).
//!
//! ```text
//! ExecutionProofEnvelope(Container):
//!     proof_data: ByteList[MAX_PROOF_SIZE]
//!     proof_type: uint8
//!     beacon_block_root: Root
//! SignedExecutionProofEnvelope(Container):
//!     message: ExecutionProofEnvelope
//!     validator_index: ValidatorIndex
//!     signature: BLSSignature
//! PublicInput(ProgressiveContainer(active_fields=[1, 1, 1, 1])):
//!     new_payload_request_root: Root
//!     successful_validation: boolean
//!     chain_id: uint64
//!     schema_id: uint16
//! ```

use sha2::{Digest, Sha256};

pub type Root = [u8; 32];

/// `MAX_PROOF_SIZE` (consensus-specs eip8025).
pub const MAX_PROOF_SIZE: usize = 4_194_304;

/// `STATELESS_INPUT_SCHEMA_ID`.
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

pub fn hash(a: &[u8; 32], b: &[u8; 32]) -> Root {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn zero_hash(depth: usize) -> Root {
    let mut z = [0u8; 32];
    for _ in 0..depth {
        z = hash(&z, &z);
    }
    z
}

/// `merkleize(chunks, limit)`: the root of a tree of `limit` leaves (rounded
/// up to a power of two), `chunks` first and zero chunks after.
pub fn merkleize(chunks: &[Root], limit: usize) -> Root {
    assert!(chunks.len() <= limit.max(1), "merkleize: more chunks than the limit");
    let depth = limit.max(1).next_power_of_two().trailing_zeros() as usize;
    let mut level: Vec<Root> = chunks.to_vec();
    for d in 0..depth {
        if level.is_empty() {
            return zero_hash(depth);
        }
        if level.len() % 2 == 1 {
            level.push(zero_hash(d));
        }
        level = level.chunks(2).map(|p| hash(&p[0], &p[1])).collect();
    }
    level.first().copied().unwrap_or([0u8; 32])
}

/// EIP-7916 `merkleize_progressive(chunks, num_leaves=1)`.
pub fn merkleize_progressive(chunks: &[Root], num_leaves: usize) -> Root {
    if chunks.is_empty() {
        return [0u8; 32];
    }
    let n = num_leaves.min(chunks.len());
    hash(
        &merkleize(&chunks[..n], num_leaves),
        &merkleize_progressive(&chunks[n..], num_leaves * 4),
    )
}

pub fn mix_in_length(root: &Root, len: usize) -> Root {
    hash(root, &uint_chunk(len as u64))
}

/// A little-endian uintN packed into one chunk.
pub fn uint_chunk(v: u64) -> Root {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

fn pack_bytes(data: &[u8]) -> Vec<Root> {
    data.chunks(32)
        .map(|s| {
            let mut c = [0u8; 32];
            c[..s.len()].copy_from_slice(s);
            c
        })
        .collect()
}

/// `hash_tree_root(ByteList[max_len](data))`.
pub fn byte_list_root(data: &[u8], max_len: usize) -> Root {
    mix_in_length(&merkleize(&pack_bytes(data), max_len.div_ceil(32)), data.len())
}

/// ZisK's EIP-8025 `ProofType`; zisk-proof-engine serves the same value.
pub const ZISK_PROOF_TYPE: u8 = 6;

/// `ExecutionProofEnvelope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProofEnvelope {
    pub proof_data: Vec<u8>,
    pub proof_type: u8,
    pub beacon_block_root: Root,
}

impl ExecutionProofEnvelope {
    pub fn hash_tree_root(&self) -> Root {
        let fields = [
            byte_list_root(&self.proof_data, MAX_PROOF_SIZE),
            uint_chunk(self.proof_type as u64),
            self.beacon_block_root,
        ];
        merkleize(&fields, fields.len())
    }

    /// Fixed part: offset(proof_data) ‖ proof_type ‖ beacon_block_root, then
    /// the proof bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        const FIXED: u32 = 4 + 1 + 32;
        out.extend_from_slice(&FIXED.to_le_bytes());
        out.push(self.proof_type);
        out.extend_from_slice(&self.beacon_block_root);
        out.extend_from_slice(&self.proof_data);
    }
}

/// `SignedExecutionProofEnvelope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedExecutionProofEnvelope {
    pub message: ExecutionProofEnvelope,
    pub validator_index: u64,
    pub signature: [u8; 96],
}

impl SignedExecutionProofEnvelope {
    /// Fixed part: offset(message) ‖ validator_index ‖ signature, then the
    /// message.
    pub fn encode(&self, out: &mut Vec<u8>) {
        const FIXED: u32 = 4 + 8 + 96;
        out.extend_from_slice(&FIXED.to_le_bytes());
        out.extend_from_slice(&self.validator_index.to_le_bytes());
        out.extend_from_slice(&self.signature);
        self.message.encode(out);
    }
}

/// SSZ of a list of variable-size `SignedExecutionProofEnvelope`s (the
/// `POST /eth/v1/beacon/execution_proofs` body; a `ProgressiveList` and a
/// `List` serialize alike): one offset per element, then the elements.
pub fn encode_signed_list(items: &[SignedExecutionProofEnvelope]) -> Vec<u8> {
    let bodies: Vec<Vec<u8>> = items
        .iter()
        .map(|s| {
            let mut b = Vec::new();
            s.encode(&mut b);
            b
        })
        .collect();
    let mut out = Vec::new();
    let mut offset = 4 * items.len();
    for b in &bodies {
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += b.len();
    }
    for b in &bodies {
        out.extend_from_slice(b);
    }
    out
}

/// EIP-8025 `PublicInput`, the statement a proof attests: the guest commits
/// only `new_payload_request_root`; the ExEx supplies the other three.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInput {
    pub new_payload_request_root: Root,
    pub successful_validation: bool,
    pub chain_id: u64,
    pub schema_id: u16,
}

impl PublicInput {
    pub fn new(new_payload_request_root: Root, chain_id: u64) -> Self {
        Self {
            new_payload_request_root,
            successful_validation: true,
            chain_id,
            schema_id: STATELESS_INPUT_SCHEMA_ID,
        }
    }

    /// EIP-7495 progressive container: `merkleize_progressive` over the field
    /// roots, mixed with the active-fields bitvector (`0b1111`).
    pub fn hash_tree_root(&self) -> Root {
        let fields = [
            self.new_payload_request_root,
            uint_chunk(self.successful_validation as u64),
            uint_chunk(self.chain_id),
            uint_chunk(self.schema_id as u64),
        ];
        let mut active = [0u8; 32];
        active[0] = 0b1111;
        hash(&merkleize_progressive(&fields, 1), &active)
    }
}

/// `compute_domain(domain_type, fork_version, genesis_validators_root)`.
pub fn compute_domain(domain_type: [u8; 4], fork_version: [u8; 4], gvr: &Root) -> Root {
    let mut version = [0u8; 32];
    version[..4].copy_from_slice(&fork_version);
    let fork_data_root = hash(&version, gvr);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// `compute_signing_root(object, domain)` from the object's root.
pub fn signing_root(object_root: &Root, domain: &Root) -> Root {
    hash(object_root, domain)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Generated with remerkleable (consensus-specs' SSZ library); see
    // `README.md` "Test vectors".
    pub(crate) fn proof() -> Vec<u8> {
        (0..1000u32).map(|i| ((i * 7 + 3) & 0xff) as u8).collect()
    }
    pub(crate) fn envelope() -> ExecutionProofEnvelope {
        ExecutionProofEnvelope { proof_data: proof(), proof_type: 3, beacon_block_root: [0x11; 32] }
    }

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn envelope_root() {
        assert_eq!(
            envelope().hash_tree_root().to_vec(),
            h("8267934a2d8e80431ba3e572d271a8799cd0d74cb642c018d2db9922b01dda31")
        );
        let empty = ExecutionProofEnvelope { proof_data: vec![], proof_type: 0, beacon_block_root: [0; 32] };
        assert_eq!(
            empty.hash_tree_root().to_vec(),
            h("f8f5b2c69e9e9608d42685351a7655c35d49cf932b4525bcdfcc411b43f5440c")
        );
    }

    #[test]
    fn domain_and_signing_root() {
        let domain = compute_domain([0x0f, 0, 0, 0], [0x90, 0, 0, 0x75], &[0x22; 32]);
        assert_eq!(
            domain.to_vec(),
            h("0f0000004d0ee20c78abce093a61fadd5305569698cebcfb846b82acc5e29b51")
        );
        assert_eq!(
            signing_root(&envelope().hash_tree_root(), &domain).to_vec(),
            h("fe55b4143926a7617d928a66b2ff88a851745245da1dbc516a2ab2756cf182c8")
        );
    }

    #[test]
    fn signed_list_encoding() {
        let mut sig = [0u8; 96];
        sig.copy_from_slice(&h("95d111532e172596c754f7158cc175fd03bcfd1c09c500fc395cfcc5aa9d765ef7a3194e695407da0c26370ed638e2470c103fc32e72cbc4c54709588ffdde5f853c45cec64360524ab456df75125578d5a9437d0c73863f15b5cabd04bdc343"));
        let signed = SignedExecutionProofEnvelope { message: envelope(), validator_index: 1234, signature: sig };
        let mut one = Vec::new();
        signed.encode(&mut one);
        assert_eq!(one.len(), 1145);
        assert_eq!(
            Sha256::digest(&one).to_vec(),
            h("567855fb06d25ddb6166815fb691f8f088bf90744bcde96ae896840d554902fc")
        );
        let list = encode_signed_list(&[signed.clone(), signed]);
        assert_eq!(list.len(), 2298);
        assert_eq!(
            Sha256::digest(&list).to_vec(),
            h("34431d1dd3a284dc1c8b8f6af3d2cc04a603f80d45d8deeb638985e498e4dfb0")
        );
    }

    #[test]
    fn public_input_root() {
        assert_eq!(
            PublicInput::new([0x33; 32], 11155111).hash_tree_root().to_vec(),
            h("e987b9bf4d36122cc8fdb920303f01be30a0e3c2400edf3238437b07a694e9bb")
        );
    }
}
