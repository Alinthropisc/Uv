use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VulnSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl VulnSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    pub check: &'static str,
    pub severity: VulnSeverity,
    pub vulnerable: bool,
    pub detail: String,
    pub cve: Option<&'static str>,
}

impl VulnResult {
    pub fn vuln(check: &'static str, severity: VulnSeverity, detail: impl Into<String>) -> Self {
        Self {
            check,
            severity,
            vulnerable: true,
            detail: detail.into(),
            cve: None,
        }
    }
    pub fn safe(check: &'static str) -> Self {
        Self {
            check,
            severity: VulnSeverity::Info,
            vulnerable: false,
            detail: "not vulnerable".into(),
            cve: None,
        }
    }
    pub fn with_cve(mut self, cve: &'static str) -> Self {
        self.cve = Some(cve);
        self
    }
}

#[async_trait]
pub trait Checker: Send + Sync {
    fn name(&self) -> &'static str;
    /// Ports this check applies to. Empty = check is caller-triggered.
    fn ports(&self) -> &'static [u16];
    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult;
}

/// Runs all registered checkers against (ip, port).
pub struct VulnEngine {
    checkers: Vec<Box<dyn Checker>>,
}

impl VulnEngine {
    pub fn new() -> Self {
        Self {
            checkers: Vec::new(),
        }
    }

    pub fn register(mut self, c: impl Checker + 'static) -> Self {
        self.checkers.push(Box::new(c));
        self
    }

    /// Run checks whose port list includes `port` (or all if port list empty).
    pub async fn run(&self, ip: IpAddr, port: u16) -> Vec<VulnResult> {
        let mut results = Vec::new();
        for checker in &self.checkers {
            let ports = checker.ports();
            if ports.is_empty() || ports.contains(&port) {
                results.push(checker.check(ip, port).await);
            }
        }
        results
    }

    /// Run ALL checkers regardless of port.
    pub async fn run_all(&self, ip: IpAddr, port: u16) -> Vec<VulnResult> {
        let mut results = Vec::new();
        for checker in &self.checkers {
            results.push(checker.check(ip, port).await);
        }
        results
    }

    /// Build the default engine with all built-in checks.
    pub fn default_engine() -> Self {
        use crate::checks::{
            anon_ftp::AnonFtp, confluence_rce::ConfluenceRce, default_creds::DefaultCreds,
            docker_api::DockerApi, elasticsearch_noauth::ElasticsearchNoAuth,
            etcd_noauth::EtcdNoAuth, eternalblue::EternalBlue, gitlab_rce::GitLabRce,
            http_open_proxy::HttpOpenProxy, kubernetes_api::KubernetesApi, log4shell::Log4Shell,
            memcached_noauth::MemcachedNoAuth, mongodb_noauth::MongoDbNoAuth,
            mqtt_noauth::MqttNoAuth, printnightmare::PrintNightmare, proxylogon::ProxyLogon,
            redis_noauth::RedisNoAuth, shellshock::Shellshock, smb_signing::SmbSigning,
            spring4shell::Spring4Shell, ssl_heartbleed::SslHeartbleed, vnc_noauth::VncNoAuth,
        };
        Self::new()
            .register(SslHeartbleed)
            .register(AnonFtp)
            .register(RedisNoAuth)
            .register(MongoDbNoAuth)
            .register(ElasticsearchNoAuth)
            .register(DockerApi)
            .register(KubernetesApi)
            .register(HttpOpenProxy)
            .register(SmbSigning)
            .register(DefaultCreds::new())
            .register(MemcachedNoAuth)
            .register(VncNoAuth)
            .register(MqttNoAuth)
            .register(EtcdNoAuth)
            .register(Shellshock)
            .register(EternalBlue)
            .register(Spring4Shell)
            .register(Log4Shell)
            .register(ProxyLogon)
            .register(PrintNightmare)
            .register(ConfluenceRce)
            .register(GitLabRce)
    }
}

impl Default for VulnEngine {
    fn default() -> Self {
        Self::new()
    }
}
