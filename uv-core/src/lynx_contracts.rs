use async_trait::async_trait;
use std::{io, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};


pub trait UvLynxDuplex: AsyncRead + AsyncWrite + Unpin + Send {

}


impl <T: AsyncRead + AsyncWrite + Unpin + Send> UvLynxDuplex for T {

}

pub type UvLynxBoxedStream = Box<dyn UvLynxDuplex>;

// the

#[derive(Debug, Clone)]
pub struct UvLynxEndpoint {
    pub host: String,
    pub port: u16,
}


#[async_trait]
pub trait UvLynxConnectionFactory: Send + Sync {
    async fn uv_lynx_connect(&self, target: &UvLynxEndpoint) -> io::Result<UvLynxBoxedStream>;
}


#[async_trait]
pub trait UvLynxAcceptor: Send + Sync {
    async fn uv_lynx_accept(&self) -> io::Result<(UvLynxBoxedStream, SocketAddr)>;
}


#[async_trait]
pub trait UvLynxProxyClient: Send + Sync {
    async fn uv_lynx_negotiate(&self, stream: UvLynxBoxedStream, target: UvLynxEndpoint) -> io::Result<UvLynxBoxedStream>;
}


pub trait UvLynxAccessControl: Send + Sync {
    fn uv_lynx_is_allowed(&self, addr: std::net::IpAddr) -> bool;
}


pub trait UvLynxEventSink: Send + Sync {
    fn uv_lynx_on_connect(&self, peer: SocketAddr) {

    }

    fn uv_lynx_on_disconnect(&self, peer: SocketAddr) {
        
    }

    fn uv_lynx_on_error(&self, err: &str) {
        
    }
}

pub struct UvLynxNullSink;


impl UvLynxEventSink for UvLynxNullSink {

}


#[async_trait]
pub trait UvLynxPlugin: Send + Sync {
    async fn uv_lynx_stream(&self, stream: UvLynxBoxedStream, peer: SocketAddr) -> io::Result<UvLynxBoxedStream> {
        Ok(stream)
    }
}










