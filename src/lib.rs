//! **uv** — Ultra-fast async port scanner.
//!
//! Combines masscan-level raw-socket throughput (target: 10M pps) with
//! nmap-style intelligent probe dispatch, built on Rust async/await and a
//! C23 network engine in `net/` / `proto/`.
//!
//! ## Quick example
//!
//! ```rust
//! use async_std::task::block_on;
//! use std::{net::IpAddr, time::Duration};
//!
//! use uv::input::{PortRange, ScanOrder};
//! use uv::port_strategy::PortStrategy;
//! use uv::scanner::Scanner;
//!
//! fn main() {
//!     let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
//!     let range = PortRange { start: 1, end: 1_000 };
//!     let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
//!     let scanner = Scanner::new(
//!         &addrs,
//!         10,
//!         Duration::from_millis(100),
//!         1,
//!         true,
//!         strategy,
//!         true,
//!         vec![9000],
//!         false,
//!     );
//!     let scan_result = block_on(scanner.run());
//!     println!("{:?}", scan_result);
//! }
//! ```
#![allow(clippy::needless_doctest_main)]

pub mod tui;

pub mod input;

pub mod scanner;

pub mod port_strategy;

pub mod benchmark;

pub mod scripts;

pub mod address;

pub mod probe;

pub mod generated;
