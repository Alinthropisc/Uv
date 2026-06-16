// mqtt-noauth — sends MQTT CONNECT packet without credentials.
// CONNACK with return code 0 = broker allows anonymous access (CRITICAL).

use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct MqttNoAuth;

#[async_trait]
impl Checker for MqttNoAuth {
    fn name(&self) -> &'static str {
        "mqtt-noauth"
    }
    fn ports(&self) -> &'static [u16] {
        &[1883, 8883]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let addr = std::net::SocketAddr::new(ip, port);
        let dur = Duration::from_millis(3000);
        let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await else {
            return VulnResult::safe(self.name());
        };

        // MQTT 3.1.1 CONNECT packet (anonymous, no user/pass)
        // Fixed header: 0x10 (CONNECT), remaining length = 14
        // Variable header: protocol name "MQTT"(4) + len(2) + level(1) + flags(1) + keepalive(2)
        // Payload: client ID "uv" (2 bytes len + 2 bytes data)
        #[rustfmt::skip]
        let connect: &[u8] = &[
            0x10, 0x10,             // CONNECT, remaining=16
            0x00, 0x04,             // protocol name length=4
            b'M', b'Q', b'T', b'T',// "MQTT"
            0x04,                   // protocol level = 3.1.1
            0x00,                   // connect flags: no clean session, no will, no user/pass
            0x00, 0x3c,             // keep-alive = 60s
            0x00, 0x02,             // client ID length = 2
            b'u', b'v',             // client ID = "uv"
        ];

        if timeout(dur, stream.write_all(connect)).await.is_err() {
            return VulnResult::safe(self.name());
        }

        // Read CONNACK (4 bytes: 0x20 0x02 <session> <return_code>)
        let mut buf = [0u8; 4];
        let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await else {
            return VulnResult::safe(self.name());
        };
        if n >= 4 && buf[0] == 0x20 && buf[3] == 0x00 {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::High,
                format!(
                    "{ip}:{port} — MQTT broker accepts anonymous connections (no auth required)"
                ),
            )
        } else {
            VulnResult::safe(self.name())
        }
    }
}
