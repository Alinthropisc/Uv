fn main() {
    cc::Build::new()
        .std("c11")
        .flag_if_supported("-O2")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-fno-strict-aliasing")
        .include("osscan")
        .files(["osscan/osscan.c", "osscan/fp-db.c"])
        .compile("uv_osscan");

    println!("cargo:rerun-if-changed=osscan/osscan.c");
    println!("cargo:rerun-if-changed=osscan/osscan.h");
    println!("cargo:rerun-if-changed=osscan/fp-db.c");
    println!("cargo:rerun-if-changed=osscan/fp-db.h");
}
