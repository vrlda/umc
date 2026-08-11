fn main() {
    prost_build::Config::new()
        .compile_protos(&["../../api/umc.proto"], &["../../api"])
        .expect("compile umc.proto");
    println!("cargo:rerun-if-changed=../../api/umc.proto");
}
