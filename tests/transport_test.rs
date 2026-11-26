use std::{fs, path::PathBuf, time::Duration};

use anyhow::Result;
use ltr_cli::{
    shared::{ClientMessage, Delimited},
    transport,
};
use rcgen::generate_simple_self_signed;
use tokio::net::TcpListener;
use uuid::Uuid;

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ltr-{name}-{}", Uuid::new_v4()))
}

fn tofu_options(port: u16, store_path: &std::path::Path) -> transport::ClientTlsOptions<'_> {
    transport::ClientTlsOptions {
        server_name: Some("localhost"),
        tofu_host: Box::leak(format!("127.0.0.1:{port}").into_boxed_str()),
        tofu_store_path: Some(store_path),
        ..Default::default()
    }
}

#[test]
fn generated_server_tls_material_is_persisted() -> Result<()> {
    let cert_path = temp_path("generated-cert.pem");
    let key_path = temp_path("generated-key.pem");

    let (_, first) = transport::load_or_generate_server_tls_at(&cert_path, &key_path, None)?;
    let (_, second) = transport::load_or_generate_server_tls_at(&cert_path, &key_path, None)?;

    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(first.cert_path, cert_path);
    assert_eq!(first.key_path, key_path);

    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
    Ok(())
}

#[tokio::test]
async fn tls_control_port_rejects_plaintext_client() -> Result<()> {
    let cert_path = temp_path("plaintext-reject-cert.pem");
    let key_path = temp_path("plaintext-reject-key.pem");
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()])?;
    fs::write(&cert_path, certificate.cert.pem())?;
    fs::write(&key_path, certificate.signing_key.serialize_pem())?;
    let server_tls = transport::load_server_tls(&cert_path, &key_path, None)?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        // A plaintext ClientHello is not a TLS handshake and must be refused.
        transport::accept(stream, Some(&server_tls))
            .await
            .map(|_| ())
    });

    let mut plaintext = Delimited::new(transport::connect("127.0.0.1", port, None).await?);
    let _ = plaintext.send(ClientMessage::Hello(7001)).await;

    assert!(
        server.await?.is_err(),
        "a TLS-enabled control port must reject plaintext clients"
    );
    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
    Ok(())
}

#[tokio::test]
async fn invalid_tls_fingerprint_and_ca_are_rejected() -> Result<()> {
    let cert_path = temp_path("invalid-cert.pem");
    let key_path = temp_path("invalid-key.pem");
    let wrong_ca_path = temp_path("wrong-ca.pem");
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let wrong_ca = generate_simple_self_signed(vec!["localhost".to_string()])?;
    fs::write(&cert_path, certificate.cert.pem())?;
    fs::write(&key_path, certificate.signing_key.serialize_pem())?;
    fs::write(&wrong_ca_path, wrong_ca.cert.pem())?;

    let server_tls = transport::load_server_tls(&cert_path, &key_path, None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        transport::accept(stream, Some(&server_tls)).await
    });

    let bad_fingerprint = "00".repeat(32);
    let client_tls = transport::load_client_tls(
        transport::ClientTlsOptions {
            fingerprint: Some(&bad_fingerprint),
            server_name: Some("localhost"),
            tofu_host: "localhost:7835",
            ..Default::default()
        },
        "localhost",
    )?;
    let err = transport::connect("127.0.0.1", port, Some(&client_tls))
        .await
        .err()
        .expect("a bad fingerprint must be rejected");
    assert!(
        !format!("{err:#}").contains("--no-tls"),
        "trust failures must not suggest --no-tls: {err:#}"
    );
    let _ = server.await;

    let server_tls = transport::load_server_tls(&cert_path, &key_path, None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        transport::accept(stream, Some(&server_tls)).await
    });
    let client_tls = transport::load_client_tls(
        transport::ClientTlsOptions {
            ca_path: Some(&wrong_ca_path),
            server_name: Some("localhost"),
            tofu_host: "localhost:7835",
            ..Default::default()
        },
        "localhost",
    )?;
    let err = transport::connect("127.0.0.1", port, Some(&client_tls))
        .await
        .err()
        .expect("an unknown CA must be rejected");
    assert!(
        !format!("{err:#}").contains("--no-tls"),
        "trust failures must not suggest --no-tls: {err:#}"
    );
    let _ = server.await;

    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
    let _ = fs::remove_file(wrong_ca_path);
    Ok(())
}

#[tokio::test]
async fn tofu_trusts_first_fingerprint_then_rejects_changes() -> Result<()> {
    let cert_path = temp_path("tofu-cert.pem");
    let key_path = temp_path("tofu-key.pem");
    let store_path = temp_path("tofu-known-hosts");
    let replacement_cert_path = temp_path("tofu-cert-2.pem");
    let replacement_key_path = temp_path("tofu-key-2.pem");
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()])?;
    fs::write(&cert_path, certificate.cert.pem())?;
    fs::write(&key_path, certificate.signing_key.serialize_pem())?;
    let replacement = generate_simple_self_signed(vec!["localhost".to_string()])?;
    fs::write(&replacement_cert_path, replacement.cert.pem())?;
    fs::write(
        &replacement_key_path,
        replacement.signing_key.serialize_pem(),
    )?;

    // First connection: TOFU records the fingerprint and succeeds.
    let server_tls = transport::load_server_tls(&cert_path, &key_path, None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut framed = Delimited::new(transport::accept(stream, Some(&server_tls)).await?);
        let message = framed.recv::<ClientMessage>().await?;
        anyhow::ensure!(matches!(message, Some(ClientMessage::Hello(1))));
        Ok::<_, anyhow::Error>(())
    });
    let client_tls = transport::load_client_tls(tofu_options(port, &store_path), "localhost")?;
    let mut stream =
        Delimited::new(transport::connect("127.0.0.1", port, Some(&client_tls)).await?);
    assert!(client_tls.take_trust_note().is_some());
    stream.send(ClientMessage::Hello(1)).await?;
    server.await??;
    assert!(store_path.exists());
    let trusted_fingerprint = fs::read_to_string(&store_path)?
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| line.split_once(' ').map(|(_, fp)| fp.to_string()))
        .expect("store should contain a fingerprint");

    // Same `ClientTlsConfig` (long-lived client), different certificate: the
    // in-memory pin must reject it even though the store was the source of
    // truth only at startup. This is the auto-reconnect MITM scenario: the
    // replacement server must listen on the SAME port (same tofu host key).
    let server_tls =
        transport::load_server_tls(&replacement_cert_path, &replacement_key_path, None)?;
    let mut listener = None;
    for _ in 0..100 {
        listener = TcpListener::bind(("127.0.0.1", port)).await.ok();
        if listener.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let listener = listener.expect("original port should be reusable");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let _ = transport::accept(stream, Some(&server_tls)).await;
        Ok::<_, anyhow::Error>(())
    });
    assert!(
        transport::connect("127.0.0.1", port, Some(&client_tls))
            .await
            .is_err(),
        "in-memory TOFU pin must reject a changed certificate on reconnect"
    );
    let _ = server.await;
    // The failed handshake must not have re-pinned the replacement cert: the
    // store still carries the original fingerprint only.
    let store_after = fs::read_to_string(&store_path)?;
    assert!(store_after.contains(&trusted_fingerprint));
    assert_eq!(
        store_after
            .lines()
            .filter(|line| !line.starts_with('#'))
            .count(),
        1,
        "failed handshake must not add a second pin"
    );

    // Same host entry, different certificate, fresh process (new config
    // loads the store): hard failure with guidance.
    let server_tls =
        transport::load_server_tls(&replacement_cert_path, &replacement_key_path, None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let _ = transport::accept(stream, Some(&server_tls)).await;
        Ok::<_, anyhow::Error>(())
    });
    // Seed the store for this port with the ORIGINAL certificate's
    // fingerprint so the replacement certificate must be rejected.
    fs::write(
        &store_path,
        format!("127.0.0.1:{port} {trusted_fingerprint}\n"),
    )?;
    let client_tls = transport::load_client_tls(tofu_options(port, &store_path), "localhost")?;
    assert!(transport::connect("127.0.0.1", port, Some(&client_tls))
        .await
        .is_err());
    let _ = server.await;

    for path in [
        &cert_path,
        &key_path,
        &store_path,
        &replacement_cert_path,
        &replacement_key_path,
    ] {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

#[tokio::test]
async fn tls_client_does_not_fall_back_to_plaintext() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A plaintext JSON server answers the TLS ClientHello with plaintext JSON,
    // which is invalid as a TLS record. The client must fail, not retry.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0u8; 1];
        let read = stream.read(&mut buf).await?;
        anyhow::ensure!(read > 0);
        stream.write_all(b"\"Heartbeat\"\0").await?;
        drop(stream);

        // No plaintext retry may arrive.
        if tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .is_ok()
        {
            anyhow::bail!("a plaintext retry followed a failed TLS handshake");
        }
        Ok::<_, anyhow::Error>(())
    });

    let store_path = temp_path("negotiate-known-hosts");
    let client_tls = transport::load_client_tls(tofu_options(port, &store_path), "localhost")?;
    let result = transport::connect("127.0.0.1", port, Some(&client_tls)).await;
    assert!(
        result.is_err(),
        "a non-TLS peer must not trigger plaintext fallback"
    );
    server.await??;
    let _ = fs::remove_file(store_path);
    Ok(())
}

#[tokio::test]
async fn tls_handshake_against_plaintext_peer_suggests_no_tls() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    // A peer that closes the connection during the handshake, as a non-TLS
    // relay does when it cannot parse the ClientHello.
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        drop(stream);
        Ok::<(), anyhow::Error>(())
    });
    let bad_fingerprint = "00".repeat(32);
    let client_tls = transport::load_client_tls(
        transport::ClientTlsOptions {
            fingerprint: Some(&bad_fingerprint),
            server_name: Some("localhost"),
            tofu_host: "localhost:7835",
            ..Default::default()
        },
        "localhost",
    )?;
    let err = transport::connect("127.0.0.1", port, Some(&client_tls))
        .await
        .err()
        .expect("a peer that closes during the handshake must fail");
    assert!(
        format!("{err:#}").contains("--no-tls"),
        "a non-TLS peer should get the --no-tls hint: {err:#}"
    );
    server.await??;
    Ok(())
}

#[tokio::test]
async fn tls_eof_does_not_trigger_plaintext_retry() -> Result<()> {
    use tokio::io::AsyncReadExt;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        drop(stream);
        if tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .is_ok()
        {
            anyhow::bail!("plaintext retry must not follow an EOF");
        }
        Ok::<_, anyhow::Error>(())
    });

    let store_path = temp_path("disconnect-known-hosts");
    let client_tls = transport::load_client_tls(tofu_options(port, &store_path), "localhost")?;
    let result = transport::connect("127.0.0.1", port, Some(&client_tls)).await;
    assert!(
        result.is_err(),
        "an EOF must not trigger plaintext fallback"
    );
    peer.await??;
    let _ = fs::remove_file(store_path);
    Ok(())
}
