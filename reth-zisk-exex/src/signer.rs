//! Validator BLS key: EIP-2335 keystore decryption and signing of
//! `ExecutionProofEnvelope`s (consensus-specs eip8025: domain
//! `DOMAIN_EXECUTION_PROOF`, fork version of the referenced block's epoch).

use std::path::Path;

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::ssz::{
    compute_domain, signing_root, ExecutionProofEnvelope, Root, SignedExecutionProofEnvelope,
};

/// `DOMAIN_EXECUTION_PROOF` (consensus-specs eip8025).
pub const DOMAIN_EXECUTION_PROOF: [u8; 4] = [0x0f, 0, 0, 0];

/// Proof-of-possession ciphersuite of the consensus layer.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub struct Signer {
    sk: blst::min_pk::SecretKey,
}

impl Signer {
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        let sk = blst::min_pk::SecretKey::from_bytes(secret)
            .map_err(|e| anyhow::anyhow!("invalid BLS secret key: {e:?}"))?;
        Ok(Self { sk })
    }

    /// A hex secret key file (devnets).
    pub fn from_secret_file(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_secret(&hex::decode(s.trim().trim_start_matches("0x")).context("secret key hex")?)
    }

    /// An EIP-2335 keystore and the file holding its password.
    pub fn from_keystore(keystore: &Path, password_file: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(keystore)
            .with_context(|| format!("reading {}", keystore.display()))?;
        let password = std::fs::read_to_string(password_file)
            .with_context(|| format!("reading {}", password_file.display()))?;
        let password = password.strip_suffix('\n').unwrap_or(&password);
        let password = password.strip_suffix('\r').unwrap_or(password);
        Self::from_secret(&decrypt_keystore(&json, password)?)
    }

    pub fn pubkey(&self) -> [u8; 48] {
        self.sk.sk_to_pk().to_bytes()
    }

    /// Sign `message` for `validator_index` under the execution-proof domain
    /// of `fork_version` (the fork at the referenced beacon block's epoch).
    pub fn sign(
        &self,
        message: ExecutionProofEnvelope,
        validator_index: u64,
        fork_version: [u8; 4],
        genesis_validators_root: &Root,
    ) -> SignedExecutionProofEnvelope {
        let domain = compute_domain(DOMAIN_EXECUTION_PROOF, fork_version, genesis_validators_root);
        let root = signing_root(&message.hash_tree_root(), &domain);
        let signature = self.sk.sign(&root, DST, &[]).to_bytes();
        SignedExecutionProofEnvelope { message, validator_index, signature }
    }
}

/// Check `signed`'s signature against `pubkey` (a local self-check before
/// the one-shot submission: a bad signature would burn this validator's
/// attempt for the block and proof type).
pub fn verify(
    signed: &SignedExecutionProofEnvelope,
    pubkey: &[u8; 48],
    fork_version: [u8; 4],
    genesis_validators_root: &Root,
) -> bool {
    let domain = compute_domain(DOMAIN_EXECUTION_PROOF, fork_version, genesis_validators_root);
    let root = signing_root(&signed.message.hash_tree_root(), &domain);
    let (Ok(pk), Ok(sig)) = (
        blst::min_pk::PublicKey::from_bytes(pubkey),
        blst::min_pk::Signature::from_bytes(&signed.signature),
    ) else {
        return false;
    };
    sig.verify(true, &root, DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
}

#[derive(Deserialize)]
struct Keystore {
    crypto: Crypto,
}
#[derive(Deserialize)]
struct Crypto {
    kdf: Module,
    checksum: Module,
    cipher: Module,
}
#[derive(Deserialize)]
struct Module {
    function: String,
    params: serde_json::Value,
    message: String,
}

/// EIP-2335 password processing: NFKD, then drop the C0, C1 and Delete
/// control codes.
fn process_password(password: &str) -> Vec<u8> {
    password
        .nfkd()
        .filter(|c| !matches!(*c as u32, 0x00..=0x1f | 0x7f..=0x9f))
        .collect::<String>()
        .into_bytes()
}

/// The secret of an EIP-2335 (version 4) keystore.
pub fn decrypt_keystore(json: &str, password: &str) -> Result<Vec<u8>> {
    let ks: Keystore = serde_json::from_str(json).context("parsing keystore")?;
    let c = ks.crypto;
    let password = process_password(password);
    let param = |k: &str| -> Result<&serde_json::Value> {
        c.kdf.params.get(k).with_context(|| format!("keystore kdf param {k} missing"))
    };
    let num = |k: &str| -> Result<u64> { param(k)?.as_u64().with_context(|| format!("kdf {k}")) };
    let salt = hex::decode(param("salt")?.as_str().context("kdf salt")?)?;
    let dklen = num("dklen")? as usize;
    if dklen < 32 {
        bail!("keystore dklen {dklen} < 32");
    }
    let mut dk = vec![0u8; dklen];
    match c.kdf.function.as_str() {
        "scrypt" => {
            let n = num("n")?;
            if !n.is_power_of_two() {
                bail!("scrypt n is not a power of two");
            }
            let params = scrypt::Params::new(n.trailing_zeros() as u8, num("r")? as u32, num("p")? as u32, dklen)
                .map_err(|e| anyhow::anyhow!("scrypt params: {e}"))?;
            scrypt::scrypt(&password, &salt, &params, &mut dk)
                .map_err(|e| anyhow::anyhow!("scrypt: {e}"))?;
        }
        "pbkdf2" => {
            if param("prf")?.as_str() != Some("hmac-sha256") {
                bail!("unsupported pbkdf2 prf");
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(&password, &salt, num("c")? as u32, &mut dk);
        }
        f => bail!("unsupported keystore kdf {f}"),
    }

    if c.checksum.function != "sha256" {
        bail!("unsupported keystore checksum {}", c.checksum.function);
    }
    let cipher_message = hex::decode(&c.cipher.message).context("cipher message")?;
    let mut h = Sha256::new();
    h.update(&dk[16..32]);
    h.update(&cipher_message);
    if h.finalize().as_slice() != hex::decode(&c.checksum.message)?.as_slice() {
        bail!("keystore checksum mismatch (wrong password?)");
    }

    if c.cipher.function != "aes-128-ctr" {
        bail!("unsupported keystore cipher {}", c.cipher.function);
    }
    let iv = hex::decode(c.cipher.params.get("iv").and_then(|v| v.as_str()).context("cipher iv")?)?;
    let mut secret = cipher_message;
    let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&dk[..16], &iv)
        .map_err(|e| anyhow::anyhow!("aes-128-ctr: {e}"))?;
    cipher.apply_keystream(&mut secret);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssz::tests::envelope;

    const SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const PUBKEY: &str = "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
    const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";

    #[test]
    fn password_processing() {
        assert_eq!(process_password(PASSWORD), hex::decode("7465737470617373776f7264f09f9491").unwrap());
    }

    // EIP-2335 test vectors.
    fn keystore(kdf: &str, checksum: &str, cipher: &str) -> String {
        format!(
            r#"{{"crypto":{{"kdf":{kdf},"checksum":{{"function":"sha256","params":{{}},"message":"{checksum}"}},
              "cipher":{{"function":"aes-128-ctr","params":{{"iv":"264daa3f303d7259501c93d997d84fe6"}},"message":"{cipher}"}}}},
              "pubkey":"{PUBKEY}","path":"","uuid":"","version":4}}"#
        )
    }

    #[test]
    fn eip2335_pbkdf2() {
        let ks = keystore(
            r#"{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""}"#,
            "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1",
            "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad",
        );
        assert_eq!(hex::encode(decrypt_keystore(&ks, PASSWORD).unwrap()), SECRET);
        assert!(decrypt_keystore(&ks, "wrong").is_err());
    }

    #[test]
    fn eip2335_scrypt() {
        let ks = keystore(
            r#"{"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""}"#,
            "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484",
            "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f",
        );
        assert_eq!(hex::encode(decrypt_keystore(&ks, PASSWORD).unwrap()), SECRET);
    }

    #[test]
    fn sign_matches_py_ecc() {
        let s = Signer::from_secret(&hex::decode(SECRET).unwrap()).unwrap();
        assert_eq!(hex::encode(s.pubkey()), PUBKEY);
        let fv = [0x90, 0, 0, 0x75];
        let signed = s.sign(envelope(), 1234, fv, &[0x22; 32]);
        assert_eq!(
            hex::encode(signed.signature),
            "95d111532e172596c754f7158cc175fd03bcfd1c09c500fc395cfcc5aa9d765ef7a3194e695407da0c26370ed638e2470c103fc32e72cbc4c54709588ffdde5f853c45cec64360524ab456df75125578d5a9437d0c73863f15b5cabd04bdc343"
        );
        assert!(verify(&signed, &s.pubkey(), fv, &[0x22; 32]));
        assert!(!verify(&signed, &s.pubkey(), [0x90, 0, 0, 0x76], &[0x22; 32]));
    }
}
