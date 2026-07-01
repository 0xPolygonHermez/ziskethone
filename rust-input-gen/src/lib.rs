//! Library entry point for `rust-input-gen`.
//!
//! Both binaries (`input-gen`, `input-gen-from-manifest`) re-use the
//! same modules — the encoder pipeline (`offline::build_binary`),
//! the in-memory bundle (`offline::OfflineSources`), the serde types
//! in `rpc`, and the typed error variants in `errors`. Keeping them
//! in a library means the offline path can also be invoked from
//! external test drivers (e.g. the planned `eest-runner` crate)
//! without spawning a subprocess.

pub mod enrich;
pub mod errors;
pub(crate) mod fetch;
pub mod live;
pub mod mpt;
pub mod offline;
pub mod rpc;
pub mod sections;
pub mod state_root;
pub mod touchset;
pub mod verify;
pub mod writer;

pub(crate) use fetch::fetch_offline_sources_online;
