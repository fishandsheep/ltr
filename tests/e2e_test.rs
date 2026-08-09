use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ltr_cli::{
    client::Client,
    server::Server,
    shared::{ClientMessage, Delimited, ServerMessage, CONTROL_PORT},
};
use rstest::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time;

/// Guard to make sure that tests are run serially, not concurrently.
static SERIAL_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct ServerGuard {
    task: JoinHandle<Result<()>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn wait_for_control_port_closed() -> Result<()> {
    for _ in 0..100 {
        if TcpStream::connect(("localhost", CONTROL_PORT))
            .await
            .is_err()
        {
            return Ok(());
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    Err(anyhow!("previous server did not release control port"))
}

/// Spawn the server and wait until the control port is accepting connections.
async fn spawn_server(secret: Option<&str>) -> Result<ServerGuard> {
    wait_for_control_port_closed().await?;

    let task = tokio::spawn(Server::new(1024..=65535, secret).listen());

    for _ in 0..50 {
        if task.is_finished() {
            return match task.await {
                Ok(Ok(())) => Err(anyhow!("server exited before listening")),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            };
        }

        match TcpStream::connect(("localhost", CONTROL_PORT)).await {
            Ok(_) => return Ok(ServerGuard { task }),
            Err(_) => time::sleep(Duration::from_millis(10)).await,
        }
    }

    Err(anyhow!("server did not start listening on control port"))
}

/// Spawns a client with randomly assigned ports, returning the listener and remote address.
async fn spawn_client(secret: Option<&str>) -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind("localhost:0").await?;
    let local_port = listener.local_addr()?.port();
    let client = Client::new("localhost", local_port, "localhost", 0, secret).await?;
    let remote_addr = ([127, 0, 0, 1], client.remote_port()).into();
    tokio::spawn(client.listen());
    Ok((listener, remote_addr))
}

async fn roundtrip(addr: SocketAddr, payload: &'static [u8]) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(payload).await?;

    let mut buf = vec![0; payload.len()];
    stream.read_exact(&mut buf).await?;
    assert_eq!(buf, payload);
    Ok(())
}

async fn wait_for_roundtrip(addr: SocketAddr, payload: &'static [u8]) -> Result<()> {
    for _ in 0..80 {
        match time::timeout(Duration::from_millis(200), roundtrip(addr, payload)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(_)) | Err(_) => time::sleep(Duration::from_millis(50)).await,
        }
    }

    Err(anyhow!("proxy did not recover before timeout"))
}

async fn run_echo_service(listener: TcpListener, expected_connections: usize) -> Result<()> {
    for _ in 0..expected_connections {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await?;
            stream.write_all(&buf[..n]).await?;
            anyhow::Ok(())
        });
    }

    Ok(())
}

#[rstest]
#[tokio::test]
async fn basic_proxy(#[values(None, Some(""), Some("abc"))] secret: Option<&str>) -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;

    let _server = spawn_server(secret).await?;
    let (listener, addr) = spawn_client(secret).await?;

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0u8; 11];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello world");

        stream.write_all(b"I can send a message too!").await?;
        anyhow::Ok(())
    });

    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(b"hello world").await?;

    let mut buf = [0u8; 25];
    stream.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"I can send a message too!");

    // Ensure that the client end of the stream is closed now.
    assert_eq!(stream.read(&mut buf).await?, 0);

    // Also ensure that additional connections do not produce any data.
    let mut stream = TcpStream::connect(addr).await?;
    assert_eq!(stream.read(&mut buf).await?, 0);

    Ok(())
}

#[rstest]
#[case(None, Some("my secret"))]
#[case(Some("my secret"), None)]
#[tokio::test]
async fn mismatched_secret(
    #[case] server_secret: Option<&str>,
    #[case] client_secret: Option<&str>,
) {
    let _guard = SERIAL_GUARD.lock().await;

    let _server = spawn_server(server_secret)
        .await
        .expect("server should start");
    assert!(spawn_client(client_secret).await.is_err());
}

#[tokio::test]
async fn invalid_address() -> Result<()> {
    // We don't need the serial guard for this test because it doesn't create a server.
    async fn check_address(to: &str, use_secret: bool) -> Result<()> {
        match Client::new("localhost", 5000, to, 0, use_secret.then_some("a secret")).await {
            Ok(_) => Err(anyhow!("expected error for {to}, use_secret={use_secret}")),
            Err(_) => Ok(()),
        }
    }
    tokio::try_join!(
        check_address("google.com", false),
        check_address("google.com", true),
        check_address("nonexistent.domain.for.demonstration", false),
        check_address("nonexistent.domain.for.demonstration", true),
        check_address("malformed !$uri$%", false),
        check_address("malformed !$uri$%", true),
    )?;
    Ok(())
}

#[tokio::test]
async fn very_long_frame() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;

    let _server = spawn_server(None).await?;
    let mut attacker = TcpStream::connect(("localhost", CONTROL_PORT)).await?;

    // Slowly send a very long frame.
    for _ in 0..10 {
        let result = attacker.write_all(&[42u8; 100000]).await;
        if result.is_err() {
            return Ok(());
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not exit after a 1 MB frame");
}

#[tokio::test]
async fn client_reconnects_after_control_eof() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;
    wait_for_control_port_closed().await?;

    let local_listener = TcpListener::bind("localhost:0").await?;
    let local_port = local_listener.local_addr()?.port();
    let remote_listener = TcpListener::bind("localhost:0").await?;
    let remote_port = remote_listener.local_addr()?.port();
    drop(remote_listener);

    let fake_control = TcpListener::bind(("localhost", CONTROL_PORT)).await?;
    let fake_task = tokio::spawn(async move {
        let (stream, _) = fake_control.accept().await?;
        let mut stream = Delimited::new(stream);
        match stream.recv_timeout().await? {
            Some(ClientMessage::Hello(port)) => assert_eq!(port, 0),
            other => return Err(anyhow!("unexpected client message: {other:?}")),
        }
        stream.send(ServerMessage::Hello(remote_port)).await?;
        anyhow::Ok(())
    });

    let client = Client::new("localhost", local_port, "localhost", 0, None).await?;
    let remote_addr = ([127, 0, 0, 1], client.remote_port()).into();
    let client_task = tokio::spawn(client.listen());
    fake_task.await??;
    wait_for_control_port_closed().await?;

    let _server = spawn_server(None).await?;
    let service = tokio::spawn(run_echo_service(local_listener, 1));

    wait_for_roundtrip(remote_addr, b"recovered").await?;

    client_task.abort();
    service.await??;
    Ok(())
}

#[tokio::test]
async fn client_reconnects_after_invalid_control_frame() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;
    wait_for_control_port_closed().await?;

    let local_listener = TcpListener::bind("localhost:0").await?;
    let local_port = local_listener.local_addr()?.port();
    let remote_listener = TcpListener::bind("localhost:0").await?;
    let remote_port = remote_listener.local_addr()?.port();
    drop(remote_listener);

    let fake_control = TcpListener::bind(("localhost", CONTROL_PORT)).await?;
    let fake_task = tokio::spawn(async move {
        let (stream, _) = fake_control.accept().await?;
        let mut stream = Delimited::new(stream);
        match stream.recv_timeout().await? {
            Some(ClientMessage::Hello(port)) => assert_eq!(port, remote_port),
            other => return Err(anyhow!("unexpected client message: {other:?}")),
        }
        stream.send(ServerMessage::Hello(remote_port)).await?;
        let mut parts = stream.into_parts();
        parts.io.write_all(&[42u8; 1024]).await?;
        time::sleep(Duration::from_millis(50)).await;
        anyhow::Ok(())
    });

    let client = Client::new("localhost", local_port, "localhost", remote_port, None).await?;
    let remote_addr = ([127, 0, 0, 1], client.remote_port()).into();
    let client_task = tokio::spawn(client.listen());
    fake_task.await??;
    wait_for_control_port_closed().await?;

    let _server = spawn_server(None).await?;
    let service = tokio::spawn(run_echo_service(local_listener, 1));

    wait_for_roundtrip(remote_addr, b"recovered").await?;

    client_task.abort();
    service.await??;
    Ok(())
}

#[test]
#[should_panic]
fn empty_port_range() {
    let min_port = 5000;
    let max_port = 3000;
    let _ = Server::new(min_port..=max_port, None);
}

#[tokio::test]
async fn half_closed_tcp_stream() -> Result<()> {
    // Check that "half-closed" TCP streams will not result in spontaneous hangups.
    let _guard = SERIAL_GUARD.lock().await;

    let _server = spawn_server(None).await?;
    let (listener, addr) = spawn_client(None).await?;

    let (mut cli, (mut srv, _)) = tokio::try_join!(TcpStream::connect(addr), listener.accept())?;

    // Send data before half-closing one of the streams.
    let mut buf = b"message before shutdown".to_vec();
    cli.write_all(&buf).await?;

    // Only close the write half of the stream. This is a half-closed stream. In the
    // TCP protocol, it is represented as a FIN packet on one end. The entire stream
    // is only closed after two FINs are exchanged and ACKed by the other end.
    cli.shutdown().await?;

    srv.read_exact(&mut buf).await?;
    assert_eq!(buf, b"message before shutdown");
    assert_eq!(srv.read(&mut buf).await?, 0); // EOF

    // Now make sure that the other stream can still send data, despite
    // half-shutdown on client->server side.
    let mut buf = b"hello from the other side!".to_vec();
    srv.write_all(&buf).await?;
    cli.read_exact(&mut buf).await?;
    assert_eq!(buf, b"hello from the other side!");

    // We don't have to think about CLOSE_RD handling because that's not really
    // part of the TCP protocol, just the POSIX streams API. It is implemented by
    // the OS ignoring future packets received on that stream.

    Ok(())
}
