use crate::error::{UvError, UvResult};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpTarget {
    Single(IpAddr),
    Cidr(CidrRange),
    Hostname(String),
}

impl IpTarget {
    pub fn parse(s: &str) -> UvResult<Self> {
        if s.contains('/') {
            Ok(IpTarget::Cidr(CidrRange::parse(s)?))
        } else if let Ok(ip) = IpAddr::from_str(s) {
            Ok(IpTarget::Single(ip))
        } else {
            Ok(IpTarget::Hostname(s.to_owned()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CidrRange {
    pub base: IpAddr,
    pub prefix_len: u8,
}

impl CidrRange {
    pub fn parse(s: &str) -> UvResult<Self> {
        let (ip_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| UvError::InvalidAddress(format!("missing prefix length in '{s}'")))?;
        let base = IpAddr::from_str(ip_str)
            .map_err(|_| UvError::InvalidAddress(format!("invalid IP '{ip_str}'")))?;
        let prefix_len: u8 = prefix_str.parse().map_err(|_| {
            UvError::InvalidAddress(format!("invalid prefix length '{prefix_str}'"))
        })?;
        let max = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(UvError::InvalidAddress(format!(
                "prefix /{prefix_len} > /{max}"
            )));
        }
        Ok(Self { base, prefix_len })
    }

    pub fn host_count(&self) -> u128 {
        match self.base {
            IpAddr::V4(_) => 1u128 << (32 - self.prefix_len),
            IpAddr::V6(_) => 1u128 << (128 - self.prefix_len),
        }
    }
}
