//! The HTTP API the beacon node calls (Lighthouse `beacon_node/proof_engine`,
//! the dapplion/eth_proof_verifier wire format):
//!
//! ```text
//! POST /v1/execution_proof_verifications?new_payload_request_root=0x..&successful_validation=true
//!      &chain_id=<u64>&schema_id=<u16>&proof_type=<u8>
//!   body: raw proof_data (application/octet-stream)
//!   200 {"status":"VALID"} | 200 {"status":"INVALID","reason":"..."}
//!   400 {"error":"..."}  malformed query or unsupported proof_type
//! GET  /v1/proof_types -> {"proof_types":[..]}
//! ```
//!
//! A 400 is a request error to Lighthouse, not a verdict on the proof.

use crate::proof::MAX_PROOF_SIZE;
use crate::verify::{self, Config, PublicInput};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

pub struct Engine {
    pub cfg: Config,
    pub proof_type: u8,
}

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/v1/execution_proof_verifications", post(verify_proof))
        .route("/v1/proof_types", get(proof_types))
        .layer(DefaultBodyLimit::max(MAX_PROOF_SIZE))
        .with_state(engine)
}

async fn proof_types(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    Json(json!({ "proof_types": [engine.proof_type] }))
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg.into() }))).into_response()
}

fn param<'a>(q: &'a HashMap<String, String>, name: &str) -> Result<&'a str, String> {
    q.get(name).map(String::as_str).ok_or_else(|| format!("missing query parameter {name}"))
}

fn parse<T: std::str::FromStr>(q: &HashMap<String, String>, name: &str) -> Result<T, String> {
    param(q, name)?.parse().map_err(|_| format!("bad {name}"))
}

/// The proof type and public input from the query string.
pub fn parse_query(q: &HashMap<String, String>) -> Result<(u8, PublicInput), String> {
    let root_hex = param(q, "new_payload_request_root")?;
    let root: [u8; 32] = hex::decode(root_hex.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("bad new_payload_request_root: expected 32 hex bytes")?;
    let successful_validation = match param(q, "successful_validation")? {
        "true" => true,
        "false" => false,
        _ => return Err("bad successful_validation".into()),
    };
    let pi = PublicInput {
        new_payload_request_root: root,
        successful_validation,
        chain_id: parse(q, "chain_id")?,
        schema_id: parse(q, "schema_id")?,
    };
    Ok((parse(q, "proof_type")?, pi))
}

async fn verify_proof(
    State(engine): State<Arc<Engine>>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let (proof_type, pi) = match parse_query(&q) {
        Ok(x) => x,
        Err(e) => return bad_request(e),
    };
    if proof_type != engine.proof_type {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported proof_type",
                "proof_type": proof_type,
                "supported": [engine.proof_type],
            })),
        )
            .into_response();
    }
    let root = hex::encode(pi.new_payload_request_root);
    let bytes = body.len();
    let t0 = Instant::now();
    let e = engine.clone();
    let result = tokio::task::spawn_blocking(move || verify::verify_execution_proof(&body, &pi, &e.cfg)).await;
    let elapsed = t0.elapsed();
    match result {
        Ok(Ok(())) => {
            info!(root, bytes, ?elapsed, "VALID");
            Json(json!({ "status": "VALID" })).into_response()
        }
        Ok(Err(reason)) => {
            warn!(root, bytes, ?elapsed, reason, "INVALID");
            Json(json!({ "status": "INVALID", "reason": reason })).into_response()
        }
        Err(join) => {
            warn!(root, bytes, ?elapsed, %join, "verifier task failed");
            Json(json!({ "status": "INVALID", "reason": "verifier task failed" })).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn engine() -> Arc<Engine> {
        Arc::new(Engine {
            cfg: Config { chain_id: 1, program_vks: vec![[1, 2, 3, 4]], setup_vk: [5, 6, 7, 8], hash: "blake3".into() },
            proof_type: 7,
        })
    }

    const ROOT: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";

    async fn call(query: &str, body: &'static [u8]) -> (StatusCode, serde_json::Value) {
        let req = Request::post(format!("/v1/execution_proof_verifications?{query}"))
            .header("content-type", "application/octet-stream")
            .body(Body::from(body))
            .unwrap();
        let resp = router(engine()).oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn request_errors_are_400() {
        let ok = format!("new_payload_request_root={ROOT}&successful_validation=true&chain_id=1&schema_id=5377");
        let (s, v) = call(&format!("{ok}&proof_type=3"), b"x").await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["supported"], json!([7]));
        let (s, _) = call("new_payload_request_root=0x12&successful_validation=true&chain_id=1&schema_id=5377&proof_type=7", b"x").await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = call(&format!("{ok}"), b"x").await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bad_proof_is_invalid() {
        let q = format!("new_payload_request_root={ROOT}&successful_validation=true&chain_id=1&schema_id=5377&proof_type=7");
        let (s, v) = call(&q, b"\x00garbage").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["status"], "INVALID");
        let q = format!("new_payload_request_root={ROOT}&successful_validation=true&chain_id=2&schema_id=5377&proof_type=7");
        let (_, v) = call(&q, b"\x00").await;
        assert_eq!(v["status"], "INVALID");
    }

    #[tokio::test]
    async fn lists_proof_types() {
        let req = Request::get("/v1/proof_types").body(Body::empty()).unwrap();
        let resp = router(engine()).oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap(), json!({ "proof_types": [7] }));
    }
}
