// Reactor pattern — async event pool inspired by nmap nsock.
// nsock concepts: pool → IODs (I/O descriptors) → events → callbacks.
// Here implemented in pure Rust/tokio — no C nsock FFI needed.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// What kind of I/O event occurred — mirrors nsock event types.
#[derive(Debug, Clone)]
pub enum IoEventKind {
    Connected,
    DataRead(Vec<u8>),
    Timeout,
    Error(String),
}

/// An I/O event returned by the pool.
#[derive(Debug, Clone)]
pub struct IoEvent {
    pub addr: SocketAddr,
    pub kind: IoEventKind,
}

/// Single I/O descriptor — wraps one target (addr + optional probe).
struct Iod {
    addr: SocketAddr,
    probe: Option<Vec<u8>>,
    timeout_ms: u64,
    max_read: usize,
}

/// Reactor / event pool — collects IODs, drives them concurrently.
/// Command pattern: submit() enqueues work; run() drains and dispatches.
pub struct EventPool {
    iods: Vec<Iod>,
    timeout_ms: u64,
    max_read: usize,
}

impl EventPool {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            iods: Vec::new(),
            timeout_ms,
            max_read: 512,
        }
    }

    pub fn max_read(mut self, n: usize) -> Self {
        self.max_read = n;
        self
    }

    /// Register a target — Command pattern (enqueue).
    pub fn submit(&mut self, addr: SocketAddr, probe: Option<Vec<u8>>) {
        self.iods.push(Iod {
            addr,
            probe,
            timeout_ms: self.timeout_ms,
            max_read: self.max_read,
        });
    }

    /// Run all IODs concurrently; collect events.
    pub async fn run(self) -> Vec<IoEvent> {
        let mut handles = Vec::with_capacity(self.iods.len());
        for iod in self.iods {
            handles.push(tokio::spawn(drive_iod(iod)));
        }
        let mut events = Vec::with_capacity(handles.len());
        for h in handles {
            if let Ok(ev) = h.await {
                events.push(ev);
            }
        }
        events
    }
}

async fn drive_iod(iod: Iod) -> IoEvent {
    let dur = Duration::from_millis(iod.timeout_ms);
    match timeout(dur, TcpStream::connect(iod.addr)).await {
        Err(_) | Ok(Err(_)) => {
            return IoEvent {
                addr: iod.addr,
                kind: IoEventKind::Timeout,
            };
        }
        Ok(Ok(mut stream)) => {
            // Send probe if provided
            if let Some(probe) = &iod.probe {
                if stream.write_all(probe).await.is_err() {
                    return IoEvent {
                        addr: iod.addr,
                        kind: IoEventKind::Timeout,
                    };
                }
            }
            // Read banner
            let mut buf = vec![0u8; iod.max_read];
            match timeout(dur, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    buf.truncate(n);
                    IoEvent {
                        addr: iod.addr,
                        kind: IoEventKind::DataRead(buf),
                    }
                }
                Ok(Err(e)) => IoEvent {
                    addr: iod.addr,
                    kind: IoEventKind::Error(e.to_string()),
                },
                _ => IoEvent {
                    addr: iod.addr,
                    kind: IoEventKind::Connected,
                },
            }
        }
    }
}
