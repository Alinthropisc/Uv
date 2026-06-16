pub mod dns;
pub mod ftp;
pub mod http;
pub mod memcached;
pub mod mongodb;
pub mod mysql;
pub mod rdp;
pub mod redis;
pub mod smb;
pub mod smtp;
pub mod ssh;
pub mod ssl;

pub use dns::DnsParser;
pub use ftp::FtpParser;
pub use http::HttpParser;
pub use memcached::MemcachedParser;
pub use mongodb::MongoDbParser;
pub use mysql::MysqlParser;
pub use rdp::RdpParser;
pub use redis::RedisParser;
pub use smb::SmbParser;
pub use smtp::SmtpParser;
pub use ssh::SshParser;
pub use ssl::SslParser;

use crate::banner::ParserChain;

/// Factory — builds the default full parser chain.
pub fn default_chain() -> ParserChain {
    ParserChain::new()
        .add(SshParser)
        .add(SslParser)
        .add(HttpParser)
        .add(FtpParser)
        .add(SmtpParser)
        .add(DnsParser)
        .add(RedisParser)
        .add(MysqlParser)
        .add(MongoDbParser)
        .add(MemcachedParser)
        .add(RdpParser)
        .add(SmbParser)
}
