//! Best-effort local-service protocol probe for the web console.
//!
//! When a tunnel starts, the console connects to the forwarded local
//! service once and fingerprints what it speaks, so the topology can
//! show the protocol and only link services a browser can actually
//! open (http/https). The probe carries no user data and validates
//! nothing — its only output is the protocol label.

#![allow(missing_docs)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::session::ServiceProto;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
const BANNER_TIMEOUT: Duration = Duration::from_millis(400);
const RESPONSE_TIMEOUT: Duration = Duration::from_millis(800);

/// Fingerprint the protocol spoken by `host:port`.
///
/// Ladder (first match wins):
/// 1. an immediate banner starting with `SSH-` → [`ServiceProto::Ssh`]
/// 2. a plaintext `GET / HTTP/1.0` answered by `HTTP/` → [`ServiceProto::Http`]
/// 3. any answer starting with a TLS record byte (`0x15` alert or `0x16`
///    handshake) → [`ServiceProto::Https`] — TLS servers answer plaintext
///    requests with an alert record
/// 4. anything else (silent, refused, closed, unknown banner) →
///    [`ServiceProto::Tcp`]
pub(crate) async fn probe_service_proto(host: &str, port: u16) -> ServiceProto {
    let target = format!("{host}:{port}");
    let stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await {
        Ok(Ok(stream)) => stream,
        _ => return ServiceProto::Tcp,
    };
    let (mut read_half, mut write_half) = stream.into_split();

    // 1. servers that greet first (SSH)
    let mut buf = [0u8; 64];
    if let Ok(Ok(n)) = timeout(BANNER_TIMEOUT, read_half.read(&mut buf)).await {
        if n == 0 {
            return ServiceProto::Tcp; // closed without a word
        }
        if buf.starts_with(b"SSH-") {
            return ServiceProto::Ssh;
        }
        return classify(&buf[..n]);
    }

    // 2-3. ask as plain HTTP, then classify the answer
    if write_half
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await
        .is_err()
    {
        return ServiceProto::Tcp;
    }
    match timeout(RESPONSE_TIMEOUT, read_half.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => classify(&buf[..n]),
        _ => ServiceProto::Tcp,
    }
}

fn classify(head: &[u8]) -> ServiceProto {
    if head.starts_with(b"HTTP/") {
        ServiceProto::Http
    } else if head.first() == Some(&0x15) || head.first() == Some(&0x16) {
        ServiceProto::Https
    } else {
        ServiceProto::Tcp
    }
}

use std::sync::Arc;

use tokio::sync::Mutex;

use super::runtime::TunnelRuntime;
use super::session::TunnelStatus;

/// Probe the tunnel's local service once it is running and record the
/// detected protocol on the runtime (visible through the next API poll).
pub(crate) fn spawn_service_probe(entry: Arc<Mutex<TunnelRuntime>>) {
    tokio::spawn(async move {
        let (host, port) = {
            let runtime = entry.lock().await;
            (runtime.config.local_host.clone(), runtime.config.local_port)
        };
        let proto = probe_service_proto(&host, port).await;
        let mut runtime = entry.lock().await;
        if matches!(
            runtime.status,
            TunnelStatus::Running | TunnelStatus::Starting
        ) {
            runtime.service_proto = Some(proto);
            runtime.push_log(format!("service protocol detected: {proto}"));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Accept one connection, read whatever the client sends, then reply.
    async fn spawn_read_then_reply(reply: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(reply).await;
            }
        });
        port
    }

    /// Accept one connection and greet before reading anything.
    async fn spawn_banner_first(banner: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(banner).await;
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn detects_http() {
        let port = spawn_read_then_reply(b"HTTP/1.0 200 OK\r\n\r\n").await;
        assert_eq!(
            probe_service_proto("127.0.0.1", port).await,
            ServiceProto::Http
        );
    }

    #[tokio::test]
    async fn detects_https_tls_alert() {
        // rustls-style fatal alert record (level 2, description 50)
        let port = spawn_read_then_reply(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32]).await;
        assert_eq!(
            probe_service_proto("127.0.0.1", port).await,
            ServiceProto::Https
        );
    }

    #[tokio::test]
    async fn detects_ssh_banner() {
        let port = spawn_banner_first(b"SSH-2.0-OpenSSH_10.6\r\n").await;
        assert_eq!(
            probe_service_proto("127.0.0.1", port).await,
            ServiceProto::Ssh
        );
    }

    #[tokio::test]
    async fn silent_service_falls_back_to_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream); // accept then close silently
            }
        });
        assert_eq!(
            probe_service_proto("127.0.0.1", port).await,
            ServiceProto::Tcp
        );
    }

    #[tokio::test]
    async fn refused_falls_back_to_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(
            probe_service_proto("127.0.0.1", port).await,
            ServiceProto::Tcp
        );
    }
}
