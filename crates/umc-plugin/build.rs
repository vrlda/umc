fn main() {
    prost_build::Config::new()
        .compile_protos(&["../../api/carrier-plugin.proto"], &["../../api"])
        .expect("compile carrier-plugin.proto");
    println!("cargo:rerun-if-changed=../../api/carrier-plugin.proto");
}
