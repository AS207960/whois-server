fn main() {
    tonic_build::compile_protos("proto/whois.proto").unwrap();
    tonic_build::compile_protos("proto/rdap.proto").unwrap();
}