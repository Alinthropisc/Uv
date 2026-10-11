use serde::{Deserialize, Serialize};

use crate::errors::{UvErrors, UvResult};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UvPort(pub u16);

impl UvPort {
    pub fn uv_new(n: u16) -> Self {
        Self(n)
    }
    pub fn uv_get(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for UvPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvPortRange {
    pub start: UvPort,
    pub end: UvPort,
}

impl UvPortRange {
    pub fn uv_new(start: u16, end: u16) -> UvResult<Self> {
        if start > end {
            return Err(UvErrors::InvalidPortRange(format!("{start}-{end}")));
        }
        Ok(Self {
            start: UvPort(start),
            end: UvPort(end),
        })
    }

    pub fn uv_single(port: u16) -> Self {
        Self {
            start: UvPort(port),
            end: UvPort(port),
        }
    }

    pub fn uv_all() -> Self {
        Self {
            start: UvPort(1),
            end: UvPort(65535),
        }
    }

    pub fn uv_count(&self) -> usize {
        (self.end.0 - self.start.0 + 1) as usize
    }

    pub fn uv_iter(&self) -> impl Iterator<Item = UvPort> {
        (self.start.0..=self.end.0).map(UvPort)
    }

    pub fn parse(s: &str) -> UvResult<Self> {
        if let Some((a, b)) = s.split_once('-') {
            let start: u16 = a.parse().map_err(|_| UvErrors::InvalidPortRange(s.to_owned()))?;
            let end: u16 = b.parse().map_err(|_| UvErrors::InvalidPortRange(s.to_owned()))?;
            Self::uv_new(start, end)
        } else {
            let p: u16 = s.parse().map_err(|_| UvErrors::InvalidPortRange(s.to_owned()))?;
            Ok(Self::uv_single(p))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UvPortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl std::fmt::Display for UvPortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UvPortState::Open => write!(f, "open"),
            UvPortState::Closed => write!(f, "closed"),
            UvPortState::Filtered => write!(f, "filtered"),
            UvPortState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}