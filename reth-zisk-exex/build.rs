// Generates the ZisK coordinator gRPC client from the vendored protos
// (0xPolygonHermez/zisk 1.4.0-alpha fix/worker-cancel-recovery, distributed/crates/coordinator-api/proto).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_well_known_types(false)
        .disable_comments(["."])
        .extern_path(".google.protobuf.Timestamp", "::prost_types::Timestamp")
        .extern_path(".google.protobuf.Duration", "::prost_types::Duration")
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["proto/zisk_coordinator_api.proto"], &["proto/"])?;
    println!("cargo:rerun-if-changed=proto/zisk_coordinator_api.proto");
    Ok(())
}
