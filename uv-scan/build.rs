fn main() {
    cc::Build::new()
        .define("_POSIX_C_SOURCE", "200809L")
        .std("c11")
        .flag_if_supported("-O2")
        .flag_if_supported("-Wall")
        .include("scan")
        .files([
            "scan/scan-dedup.c",
            "scan/scan-throttle.c",
            "scan/scan-status.c",
        ])
        .compile("uv_scan_c");

    println!("cargo:rerun-if-changed=scan/");
}
