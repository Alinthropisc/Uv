// MongoDB banner parser — OP_MSG / OP_REPLY wire protocol detection.
// MongoDB sends nothing on connect; we detect via response to isMaster.
// Here we detect if the banner looks like a BSON/wire protocol message.
// Actual probe is in uv-engine/udp.rs; this parser handles the response bytes.

use crate::banner::{BannerParser, ParsedBanner};

pub struct MongoDbParser;

impl BannerParser for MongoDbParser {
    fn name(&self) -> &'static str {
        "mongodb"
    }

    fn parse(&self, banner: &[u8], _port: u16) -> Option<ParsedBanner> {
        if banner.len() < 16 {
            return None;
        }

        // MongoDB wire protocol message header: messageLength(4) + requestID(4) + responseTo(4) + opCode(4)
        let msg_len = u32::from_le_bytes([banner[0], banner[1], banner[2], banner[3]]) as usize;
        if !(16..=48 * 1024 * 1024).contains(&msg_len) {
            return None;
        }

        let op_code = u32::from_le_bytes([banner[12], banner[13], banner[14], banner[15]]);
        // OP_REPLY = 1, OP_MSG = 2013
        if op_code != 1 && op_code != 2013 {
            return None;
        }

        // Try to find version string in the BSON response
        let version = find_version_in_bson(&banner[16..]);
        let mut pb = ParsedBanner::new("mongodb");
        if let Some(v) = version {
            pb = pb.with_version(v);
        }
        Some(pb)
    }
}

fn find_version_in_bson(data: &[u8]) -> Option<&str> {
    // Simple search for "version\0" key pattern in BSON
    let key = b"version\x00";
    let pos = data.windows(key.len()).position(|w| w == key)?;
    let val_start = pos + key.len();
    if val_start + 4 >= data.len() {
        return None;
    }
    // BSON string: type(1) + length(4) + chars + NUL
    let str_len = u32::from_le_bytes([
        data[val_start],
        data[val_start + 1],
        data[val_start + 2],
        data[val_start + 3],
    ]) as usize;
    let str_start = val_start + 4;
    if str_start + str_len > data.len() {
        return None;
    }
    std::str::from_utf8(&data[str_start..str_start + str_len.saturating_sub(1)]).ok()
}
