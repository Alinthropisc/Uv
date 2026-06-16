// uv-output: pluggable output formatters.
// Strategy pattern — swap format at runtime without changing orchestrator.

pub mod binary;
pub mod binary_read;
pub mod certs;
pub mod formatter;
pub mod greppable;
pub mod json;
pub mod ndjson;
pub mod plain;
pub mod redis_out;
pub mod unicornscan;
pub mod xml;

pub use binary::{decode_binary, encode_binary, BinaryFormatter};
pub use binary_read::{decode_to_scan, load_binary, merge};
pub use certs::CertsFormatter;
pub use formatter::{Formatter, OutputFormat};
pub use greppable::GrepFormatter;
pub use json::JsonFormatter;
pub use ndjson::NdJsonFormatter;
pub use plain::PlainFormatter;
pub use redis_out::RedisPublisher;
pub use unicornscan::UnicornscanFormatter;
pub use xml::XmlFormatter;

/// Factory — build a Formatter from an OutputFormat tag.
pub fn make_formatter(fmt: OutputFormat) -> Box<dyn Formatter> {
    match fmt {
        OutputFormat::Plain => Box::new(PlainFormatter),
        OutputFormat::Greppable => Box::new(GrepFormatter),
        OutputFormat::Json => Box::new(JsonFormatter),
        OutputFormat::Xml => Box::new(XmlFormatter),
        OutputFormat::Binary => Box::new(BinaryFormatter),
        OutputFormat::NdJson => Box::new(NdJsonFormatter),
        OutputFormat::Certs => Box::new(CertsFormatter),
        OutputFormat::Unicornscan => Box::new(UnicornscanFormatter),
    }
}
