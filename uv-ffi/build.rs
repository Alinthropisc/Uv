fn main() {
    cc::Build::new()
        .std("c2x")
        .flag_if_supported("-O2")
        .flag_if_supported("-Wall")
        .include("../net")
        .include("../proto")
        .files([
            "../net/checksum.c",
            "../net/pkt.c",
            "../net/blackrock.c",
            "../net/cookie.c",
            "../net/rate.c",
            "../proto/svcmatch.c",
        ])
        .compile("uv_c_layer");

    println!("cargo:rerun-if-changed=../net/");
    println!("cargo:rerun-if-changed=../proto/svcmatch.c");
    // rawsock_linux.c + uv-bridge.c only on Linux (need AF_PACKET + pthreads)
    #[cfg(target_os = "linux")]
    {
        cc::Build::new()
            .std("c11")
            .flag_if_supported("-O2")
            .flag_if_supported("-Wall")
            .include("ffi")
            .include("../net")
            .file("../net/rawsock_linux.c")
            .file("ffi/uv-bridge.c")
            .compile("uv_rawsock");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rerun-if-changed=ffi/uv-bridge.c");
        println!("cargo:rerun-if-changed=ffi/uv-bridge.h");
    }
}
