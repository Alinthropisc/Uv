use std::net::{IpAddr, SocketAddr};

pub fn uv_lynx_to_socket_addr(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;
    (host, port).to_socket_addrs().map(|it| it.collect())
}

pub fn uv_lynx_family_tag(a: &IpAddr) -> &'static str {
    match a {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}