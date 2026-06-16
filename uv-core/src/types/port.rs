use crate::error::{UvError, UvResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Port(pub u16);

impl Port {
    pub fn new(n: u16) -> Self {
        Self(n)
    }
    pub fn get(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: Port,
    pub end: Port,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> UvResult<Self> {
        if start > end {
            return Err(UvError::InvalidPortRange(format!("{start}-{end}")));
        }
        Ok(Self {
            start: Port(start),
            end: Port(end),
        })
    }

    pub fn single(port: u16) -> Self {
        Self {
            start: Port(port),
            end: Port(port),
        }
    }

    pub fn all() -> Self {
        Self {
            start: Port(1),
            end: Port(65535),
        }
    }

    pub fn count(&self) -> usize {
        (self.end.0 - self.start.0 + 1) as usize
    }

    pub fn iter(&self) -> impl Iterator<Item = Port> {
        (self.start.0..=self.end.0).map(Port)
    }

    pub fn parse(s: &str) -> UvResult<Self> {
        if let Some((a, b)) = s.split_once('-') {
            let start: u16 = a
                .parse()
                .map_err(|_| UvError::InvalidPortRange(s.to_owned()))?;
            let end: u16 = b
                .parse()
                .map_err(|_| UvError::InvalidPortRange(s.to_owned()))?;
            Self::new(start, end)
        } else {
            let p: u16 = s
                .parse()
                .map_err(|_| UvError::InvalidPortRange(s.to_owned()))?;
            Ok(Self::single(p))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}
