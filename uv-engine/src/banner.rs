use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use uv_core::errors::UvResult;
use uv_core::traits::UvBannerGrabber;
use uv_core::types::banner::{UvBanner, UvServiceInfo};
use uv_core::types::port::UvPort;
use uv_core::types::protocol::{UvProtocol, UvServiceKind};

pub struct UvTcpBannerGrabber {
    timeout: Duration,
    max_bytes: usize,
}

impl UvTcpBannerGrabber {
    pub fn new(timeout_ms: u32, max_bytes: usize) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms as u64),
            max_bytes,
        }
    }
}

#[async_trait]
impl UvBannerGrabber for UvTcpBannerGrabber {
    async fn grab(&self, target: IpAddr, port: Port, proto: Protocol) -> UvResult<Option<ServiceInfo>> {
        if proto != Protocol::Tcp {
            return Ok(None);
        }
        let addr = SocketAddr::new(target, port.get());
        
        let Ok(Ok(mut stream)) = timeout(self.timeout, TcpStream::connect(addr)).await else {
            return Ok(None);
        };
        let mut buf = vec![0u8; self.max_bytes];
        let n = timeout(self.timeout, stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
        
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        let banner = Banner::from_bytes(buf, false);
        let svc = UvServiceKind::from_port(port.get(), proto);
        Ok(Some(ServiceInfo::new(svc).with_banner(banner)))
    }
}
