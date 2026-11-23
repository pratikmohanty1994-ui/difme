// Generates the device side of the hub protocol from the repo's contract (api/proto), the same file the hub uses.
// protoc comes from protoc-bin-vendored, so the build needs no system protobuf compiler.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: build scripts are single-threaded; nothing else reads the environment concurrently.
    unsafe { std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?) };
    let proto = "../../api/proto/difme/payments/v1/payments.proto";
    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-changed=rules/offline_limit.wasm");
    prost_build::compile_protos(&[proto], &["../../api/proto"])?;
    Ok(())
}
