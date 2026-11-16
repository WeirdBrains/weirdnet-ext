fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bundled protoc: no system protobuf install needed.
    // SAFETY: build scripts are single-threaded.
    unsafe { std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?) };
    println!("cargo:rerun-if-changed=proto/weirdnet/ext/v1/ext.proto");
    tonic_prost_build::configure().compile_protos(&["proto/weirdnet/ext/v1/ext.proto"], &["proto"])?;
    Ok(())
}
