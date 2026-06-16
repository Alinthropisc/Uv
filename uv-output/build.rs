fn main() {
    cc::Build::new()
        .std("c11")
        .flag_if_supported("-O2")
        .flag_if_supported("-Wall")
        .include("output")
        .files(["output/output.c", "output/output-status.c"])
        .compile("uv_output_c");

    println!("cargo:rerun-if-changed=output/output.c");
    println!("cargo:rerun-if-changed=output/output.h");
    println!("cargo:rerun-if-changed=output/output-status.c");
    println!("cargo:rerun-if-changed=output/output-status.h");
}
