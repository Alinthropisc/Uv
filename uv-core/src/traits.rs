use crate::error::UvResult;
use crate::types::port::Port;
use crate::types::protocol::Protocol;
use crate::types::result::{ProbeResult, ScanResult};
use async_trait::async_trait;
use std::net::IpAddr;

#[async_trait]
pub trait Scanner: Send + Sync {
    async fn scan(&self, target: IpAddr, ports: &[Port]) -> UvResult<Vec<ProbeResult>>;
    fn protocol(&self) -> Protocol;
}

#[async_trait]
pub trait BannerGrabber: Send + Sync {
    async fn grab(
        &self,
        target: IpAddr,
        port: Port,
        proto: Protocol,
    ) -> UvResult<Option<crate::types::banner::ServiceInfo>>;
}

pub trait ResultSink: Send + Sync {
    fn push(&mut self, result: ProbeResult, host: IpAddr);
    fn finalize(self) -> ScanResult;
}

pub trait RateLimiter: Send + Sync {
    fn acquire(&self, n: u32) -> UvResult<()>;
    fn rate_pps(&self) -> u64;
}
