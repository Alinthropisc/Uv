use thiserror::Error;

pub type UvResult<T> = Result<T, UvError>;

#[derive(Debug, Error)]
pub enum UvError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS resolution failed: {0}")]
    Dns(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid port range: {0}")]
    InvalidPortRange(String),

    #[error("Rate limiter overflow: requested {requested}, burst cap {cap}")]
    RateOverflow { requested: u32, cap: u64 },

    #[error("FFI error: {0}")]
    Ffi(String),

    #[error("Scan aborted: {0}")]
    Aborted(String),

    #[error("Timeout after {ms}ms")]
    Timeout { ms: u32 },

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
