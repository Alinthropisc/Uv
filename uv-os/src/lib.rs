// uv-os: OS fingerprinting inspired by nmap FPEngine.
// Strategy + Template Method + Repository patterns.

pub mod active;
pub mod db;
pub mod fingerprint;
pub mod matcher;
pub mod probe;

pub use active::ActiveOsProber;
pub use db::OsDb;
pub use fingerprint::{OsFingerprint, OsMatch};
pub use matcher::OsMatcher;
pub use probe::{OsProbe, ProbeSpec};
