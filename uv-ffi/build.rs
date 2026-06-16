fn main() {
    let c_sources = [
        "../net/checksum.c",
        "../net/pkt.c",
        "../net/blackrock.c",
        "../net/cookie.c",
        "../net/rate.c",
        "../proto/svcmatch.c",
    ];

    // Only compile the C layer when all source files exist.
    // During CI the net/ and proto/ dirs are absent until the C submodule is populated.
    if c_sources.iter().all(|f| std::path::Path::new(f).exists()) {
        cc::Build::new()
            .std("c2x")
            .flag_if_supported("-O2")
            .flag_if_supported("-Wall")
            .include("../net")
            .include("../proto")
            .files(c_sources)
            .compile("uv_c_layer");
    }

    println!("cargo:rerun-if-changed=../net/");
    println!("cargo:rerun-if-changed=../proto/svcmatch.c");

    #[cfg(target_os = "linux")]
    {
        let rawsock_files = ["../net/rawsock_linux.c", "ffi/uv-bridge.c"];
        if rawsock_files
            .iter()
            .all(|f| std::path::Path::new(f).exists())
        {
            cc::Build::new()
                .std("c11")
                .flag_if_supported("-O2")
                .flag_if_supported("-Wall")
                .include("ffi")
                .include("../net")
                .files(rawsock_files)
                .compile("uv_rawsock");
            println!("cargo:rustc-link-lib=pthread");
        }
        println!("cargo:rerun-if-changed=ffi/uv-bridge.c");
        println!("cargo:rerun-if-changed=ffi/uv-bridge.h");
    }
}
