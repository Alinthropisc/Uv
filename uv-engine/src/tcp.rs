use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use uv_core::error::UvResult;
use uv_core::traits::{RateLimiter, Scanner};
use uv_core::types::port::Port;
use uv_core::types::protocol::Protocol;
use uv_core::types::result::ProbeResult;

pub struct TcpConnectScanner {
    timeout: Duration,
    concurrency: usize,
    limiter: Option<Arc<dyn RateLimiter>>,
}

impl TcpConnectScanner {
    pub fn new(timeout_ms: u32) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms as u64),
            concurrency: 512,
            limiter: None,
        }
    }

    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrency = n;
        self
    }

    pub fn with_limiter(mut self, lim: Arc<dyn RateLimiter>) -> Self {
        self.limiter = Some(lim);
        self
    }

    async fn probe_one(addr: SocketAddr, to: Duration, port: Port) -> ProbeResult {
        let t0 = Instant::now();
        match timeout(to, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => ProbeResult::open(port, Protocol::Tcp, t0.elapsed()),
            Ok(Err(e)) if is_refused(&e) => ProbeResult::closed(port, Protocol::Tcp),
            _ => ProbeResult::filtered(port, Protocol::Tcp),
        }
    }
}

#[async_trait]
impl Scanner for TcpConnectScanner {
    async fn scan(&self, target: IpAddr, ports: &[Port]) -> UvResult<Vec<ProbeResult>> {
        let mut results = Vec::with_capacity(ports.len());
        let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();
        let to = self.timeout;

        for &port in ports {
            // Rate limit before spawning
            if let Some(ref lim) = self.limiter {
                lim.acquire(1)?;
            }

            let addr = SocketAddr::new(target, port.get());
            tasks.push(async move { Self::probe_one(addr, to, port).await });

            // Drain when at concurrency limit
            if tasks.len() >= self.concurrency {
                if let Some(r) = tasks.next().await {
                    results.push(r);
                }
            }
        }

        // Drain remaining
        while let Some(r) = tasks.next().await {
            results.push(r);
        }

        Ok(results)
    }

    fn protocol(&self) -> Protocol {
        Protocol::Tcp
    }
}

fn is_refused(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ConnectionRefused
}
