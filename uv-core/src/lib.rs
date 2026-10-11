pub mod engine;
pub mod errors;
pub use errors::{UvResult, UvErrors, NetworkError, ProtocolError, ScriptError};
pub mod types;
pub mod config;
pub mod scan_type;
pub use scan_type::UvScanType;
pub mod timing;
pub use timing::{UvTimingParams, UvTimingTemplate};
pub mod exclude;
pub use exclude::{UvIpExcludeList, UvPortExcludeList};
pub mod traits;
pub mod lynx_contracts;
pub mod range;

pub use lynx_contracts::{UvLynxDuplex, UvLynxDuplex, UvLynxBoxedStream, UvLynxEndpoint, UvLynxConnectionFactory, UvLynxAcceptor, UvLynxProxyClient, UvLynxAccessControl, UvLynxNullSink, UvLynxEventSink, UvLynxPlugin};


pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
