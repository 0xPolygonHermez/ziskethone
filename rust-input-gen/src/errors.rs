//! Cross-module error types.
//!
//! `ReorgDetected` lives here so both `rpc.rs` (which discovers it
//! via hash checks bracketing unpinnable RPC calls) and `main.rs`
//! (which discovers it via the end-of-run reverify) can construct
//! and downcast it. Bubble up via `anyhow::Error`; `main.rs` does
//! the downcast and translates to exit code 75 (EX_TEMPFAIL).

use alloy::primitives::B256;

#[derive(thiserror::Error, Debug)]
#[error(
    "reorg detected at block {block} during {phase}: \
     expected hash {expected}, observed {actual:?}"
)]
pub struct ReorgDetected {
    pub block: u64,
    pub expected: B256,
    pub actual: Option<B256>,
    pub phase: &'static str,
}
