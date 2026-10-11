use std::net::IpAddr;

use crate::proxy::UvLynxProxyKind;

#[derive(Debug, Clone, Default)]
pub struct UvLynxConfig {
    pub listen: bool,
    pub udp: bool,
    pub keep_open: bool,
    pub unixsock: bool,
    pub host: Option<String>,
    pub port: u16,
    pub source_port: Option<u16>,
    pub source_addr: Option<IpAddr>,

    pub ssl: bool,
    pub ssl_cert: Option<String>,
    pub ssl_key: Option<String>,
    pub ssl_verify: bool,
    pub ssl_ca: Option<String>,

    pub exec_cmd: Option<String>,   // --exec
    pub sh_exec_cmd: Option<String>, // --sh-exec

    pub proxy: Option<String>,
    pub proxy_type: ProxyKind,
    pub proxy_user: Option<String>,
    pub proxy_pass: Option<String>,

    pub allow: Vec<String>,
    pub deny: Vec<String>,

    pub broker: bool,
    pub chat: bool,
    pub max_conns: usize,

    pub idle_timeout_ms: Option<u64>,
    pub crlf: bool,
}

#[derive(Default)]
pub struct UvLynxConfigBuilder(Config);



impl UvLynxConfigBuilder {
    pub fn uv_lynx_new() -> Self {
        Self(Config {
            max_conns: usize::MAX,
            ..Default::default()
        })
    }

    pub fn uv_lynx_listen(mut self, v: bool) -> Self {
        self.0.listen = v;
        self
    }

    pub fn uv_lynx_udp(mut self, v: bool) -> Self {
        self.0.udp = v;
        self
    }

    pub fn uv_lynx_host(mut self, h: impl Into<String>) -> Self {
        self.0.host = Some(h.into());
        self
    }

    pub fn uv_lynx_port(mut self, p: u16) -> Self {
        self.0.port = p;
        self
    }

    pub fn uv_lynx_ssl(mut self, v: bool) -> Self {
        self.0.ssl = v;
        self
    }

    pub fn uv_lynx_exec(mut self, c: impl Into<String>) -> Self {
        self.0.exec_cmd = Some(c.into());
        self
    }

    pub fn uv_lynx_build(self) -> Config {
        self.0
    }
}





























