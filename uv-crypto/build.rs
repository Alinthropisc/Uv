fn main() {
    // crypto-blackrock2.c has transitive masscan deps (pixie-timer, util-malloc)
    // not present in this subtree — algorithms are re-implemented in pure Rust.
    // build.rs reserved for future C stubs if those deps are added.
    println!("cargo:rerun-if-changed=crypto/");
}
