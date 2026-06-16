// uv-ffi: safe Rust wrappers over C23 net/proto layer.
// Facade pattern — one clean Rust API hiding unsafe FFI details.

pub mod pkt;
pub mod rawsock;
pub mod svcmatch;

pub use pkt::{PktBuilder, RawFrame};
pub use svcmatch::SvcDb;
