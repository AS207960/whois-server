fn main() {
    tonic_build::compile_protos("proto/rdap.proto").unwrap();
}