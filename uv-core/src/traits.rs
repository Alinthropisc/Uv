use async_trait::async_trait;
use std::net::IpAddr;

use crate::errors::UvResult;
use crate::types::port::UvPort;
use crate::types::protocol::UvProtocol;
use crate::types::result::{UvProbeResult, UvScanResult};


#[async_trait]
pub trait UvScanner: Send + Sync {
    async fn uv_scan(&self, target: IpAddr, ports: &[UvPort]) -> UvResult<Vec<UvProbeResult>>;
    fn uv_protocol(&self) -> UvProtocol;
}

#[async_trait]
pub trait UvBannerGrabber: Send + Sync {
    async fn uv_grab(&self,target: IpAddr,port: UvPort,proto: UvProtocol,) -> UvResult<Option<crate::types::banner::UvServiceInfo>>;
}

pub trait UvResultSink: Send + Sync {
    fn uv_push(&mut self, result: UvProbeResult, host: IpAddr);
    fn uv_finalize(self) -> UvScanResult;
}

pub trait UvRateLimiter: Send + Sync {
    fn uv_acquire(&self, n: u32) -> UvResult<()>;
    fn uv_rate_pps(&self) -> u64;
}




























