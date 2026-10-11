// MongoDB no-auth check — send isMaster OP_MSG, check for successful reply.
// Unauthenticated MongoDB = full DB access (read/write all collections).

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct MongoDbNoAuth;

#[async_trait]
impl Checker for MongoDbNoAuth {
    fn name(&self) -> &'static str {
        "mongodb-noauth"
    }
    fn ports(&self) -> &'static [u16] {
        &[27017, 27018, 27019]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(Some(info)) => VulnResult::vuln(
                "mongodb-noauth",
                VulnSeverity::Critical,
                format!("MongoDB accessible without authentication — {info}"),
            ),
            _ => VulnResult::safe("mongodb-noauth"),
        }
    }
}

fn probe(sa: SocketAddr) -> Option<String> {
    let timeout = Duration::from_secs(4);
    let mut sock = TcpStream::connect_timeout(&sa, timeout).ok()?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(Duration::from_secs(3))).ok();

    // OP_MSG isMaster command (MongoDB 3.6+ wire protocol)
    // Manually constructed minimal BSON: {isMaster: 1, $db: "admin"}
    let bson_doc: &[u8] = &[
        // BSON document for {isMaster:1, $db:"admin"}
        0x1b, 0x00, 0x00, 0x00, // doc length = 27
        0x10, // type int32
        b'i', b's', b'M', b'a', b's', b't', b'e', b'r', 0x00, // key "isMaster\0"
        0x01, 0x00, 0x00, 0x00, // value 1
        0x02, // type string
        b'$', b'd', b'b', 0x00, // key "$db\0"
        0x06, 0x00, 0x00, 0x00, // string length 6
        b'a', b'd', b'm', b'i', b'n', 0x00, // "admin\0"
        0x00, // doc terminator
    ];

    // OP_MSG header: msgLen(4) + reqId(4) + responseTo(4) + opCode(4=2013) + flagBits(4) + section(1+doc)
    let total_len = 4 + 4 + 4 + 4 + 4 + 1 + bson_doc.len();
    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&(total_len as u32).to_le_bytes()); // messageLength
    msg.extend_from_slice(&1u32.to_le_bytes()); // requestID
    msg.extend_from_slice(&0u32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&2013u32.to_le_bytes()); // opCode OP_MSG
    msg.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    msg.push(0x00); // section kind = body
    msg.extend_from_slice(bson_doc);

    sock.write_all(&msg).ok()?;

    let mut resp = [0u8; 512];
    let n = sock.read(&mut resp).ok()?;
    if n < 16 {
        return None;
    }

    // Check opCode in response header = OP_MSG (2013)
    let op = u32::from_le_bytes([resp[12], resp[13], resp[14], resp[15]]);
    if op != 2013 && op != 1 {
        return None;
    }

    // Look for "ismaster":true or "ok":1 in raw BSON
    let body = std::str::from_utf8(&resp[..n]).unwrap_or("");
    if body.contains("ismaster") || resp[..n].windows(2).any(|w| w == [0x01, 0x00]) {
        // Try to find version
        let version = find_bson_str(&resp[..n], b"version\x00").unwrap_or("unknown");
        return Some(version.to_string());
    }
    None
}

fn find_bson_str<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a str> {
    let pos = data.windows(key.len()).position(|w| w == key)?;
    let after = pos + key.len();
    if after + 4 >= data.len() {
        return None;
    }
    let str_len = u32::from_le_bytes([
        data[after],
        data[after + 1],
        data[after + 2],
        data[after + 3],
    ]) as usize;
    let str_start = after + 4;
    if str_start + str_len > data.len() {
        return None;
    }
    std::str::from_utf8(&data[str_start..str_start + str_len.saturating_sub(1)]).ok()
}
