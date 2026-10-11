use thiserror::Error;
use serde::{Serialize, Deserialize};


#[derive(Debug, Error, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")] // For JSON-Serialize Errors
pub enum UvErrors {
    // Net Errors
    #[error("Network Error: {0}")]
    Network(#[from] NetworkError),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Protocol parse error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Script execution failed: {0}")]
    Script(#[from] ScriptError),

    #[error("Invalid Target: {0}")]
    InvalidTarget(String),

    #[error("Scan cancelled by user")]
    Canceled,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),
}

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum NetworkError {
    #[error("Permission denied (requires root/cap_net_raw)")]
    PermissionDenied,

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Packet send failed: {0}")]
    SendFailed(String),

    #[error("Capture error: {0}")]
    CaptureFailed(String),
}


#[derive(Debug,  Error, Serialize, Deserialize)]
pub enum ProtocolError {
    #[error("Malformed packet: {0}")]
    Malformed(String),

    #[error("Unknown protocol: {0}")]
    UnknownProtocol(u8),
}


#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ScriptError {
    #[error("Syntax error: {0}")]
    Syntax(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Sandbox Violation")]
    SandboxViolation,
}



pub type UvResult<UVT> = std::result::Result<UVT, UvErrors>;













