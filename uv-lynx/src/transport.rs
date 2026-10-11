use async_trait::async_trait;
use std::io;
use tokio::net::{TcpStream, UdpSocket, UnixStream};

use uv_core::contracts::{UvLynxBoxedStream, UvLynxConnectionFactory, UvLynxEndpoint};

pub struct UvLynxConnectedUDP(pub UdpSocket);
pub struct UvLynxUDPFactory;

pub struct UvLynxUnixFactory;
pub struct UvLynxTcpFactory {
    pub source_port: Option<u16>,
    pub bind_addr: Option<std::net::IpAddr>
}



#[async_trait]
impl UvLynxConnectionFactory for UvLynxTcpFactory {
    async fn uv_lynx_connect(&self, traget: &UvLynxEndpoint) -> io::Result<UvLynxBoxedStream> {
        let addr = format!("{}:{}", traget.host, traget.port);
        let socket = tokio::net::TcpSocket::new_v4()?;

        if let Some(p) = self.source_port {
            let bind_ip = self.bind_addr.unwrap_or_else(|| "0.0.0.0".parse().unwrap());
            socket.bind(std::net::SocketAddr::new(bind_ip, p))?;
        }
        let resolved: std::net::SocketAddr = tokio::net::lookup_host(&addr).await.next().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS resolve failed"))?;
        let stream = socket.connect(resolved).await?;
        stream.set_nodelay(true).ok();
        Ok(Box::new(stream))
    }
}




impl tokio::io::AsyncRead for UvLynxConnectedUDP {
    fn uv_lynx_poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
        self.0.pool_recv(cx, buf)
    }
}


impl tokio::io::AsyncWrite for UvLynxConnectedUDP {
    fn uv_lynx_poll_write(self: std::pin::Pin<&mut self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }

    fn uv_lynx_poll_flush(self: std::pin::Pin<&mut self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn uv_lynx_poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}



#[async_trait]
impl UvLynxConnectionFactory for UvLynxUDPFactory {
    async fn uv_lynx_connect(&self, target: &UvLynxEndpoint) -> io::Result<UvLynxBoxedStream> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(format!("{}:{}", target.host, target.port)).await?;
        Ok(Box::new(ConnectedUdp(sock)))
    }
}

#[async_trait]
impl UvLynxConnectionFactory for UvLynxUnixFactory {
    async fn uv_lynx_connect(&self, target: &UvLynxEndpoint) -> io::Result<UvLynxBoxedStream> {
        let stream = UnixStream::connect(&target.host).await?;
        Ok(Box::new(stream))
    }
}

















