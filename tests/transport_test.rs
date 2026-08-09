use std::{fs, path::PathBuf};

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
async fn shared_control_port_accepts_tls_and_plaintext() -> Result<()> {
    let cert_path = temp_path("cert.pem");
    let key_path = temp_path("key.pem");
    let client_cert_path = temp_path("client-cert.pem");
    let client_key_path = temp_path("client-key.pem");
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let client_certificate = generate_simple_self_signed(vec!["ltr-client".to_string()])?;
    fs::write(&cert_path, certificate.cert.pem())?;
    fs::write(&key_path, certificate.signing_key.serialize_pem())?;
    fs::write(&client_cert_path, client_certificate.cert.pem())?;
    fs::write(
        &client_key_path,
        client_certificate.signing_key.serialize_pem(),
    )?;

    let server_tls = transport::load_server_tls(&cert_path, &key_path, Some(&client_cert_path))?;
    let client_tls = transport::load_client_tls(
        Some(&cert_path),
        None,
        Some("localhost"),
        "localhost",
        Some(&client_cert_path),
        Some(&client_key_path),
    )?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut framed = Delimited::new(transport::accept(stream, Some(&server_tls)).await?);
        let message = framed.recv::<ClientMessage>().await?;
        anyhow::ensure!(matches!(message, Some(ClientMessage::Hello(7000))));

        let (stream, _) = listener.accept().await?;
        let mut framed = Delimited::new(transport::accept(stream, Some(&server_tls)).await?);
        let message = framed.recv::<ClientMessage>().await?;
        anyhow::ensure!(matches!(message, Some(ClientMessage::Hello(7001))));
        Ok::<_, anyhow::Error>(())
    });

    let mut tls = Delimited::new(transport::connect("127.0.0.1", port, Some(&client_tls)).await?);
    tls.send(ClientMessage::Hello(7000)).await?;

    let mut plaintext = Delimited::new(transport::connect("127.0.0.1", port, None).await?);
    plaintext.send(ClientMessage::Hello(7001)).await?;

    server.await??;
    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
    let _ = fs::remove_file(client_cert_path);
    let _ = fs::remove_file(client_key_path);
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
        None,
        Some(&bad_fingerprint),
        Some("localhost"),
        "localhost",
        None,
        None,
    )?;
    assert!(transport::connect("127.0.0.1", port, Some(&client_tls))
        .await
        .is_err());
    let _ = server.await;

    let server_tls = transport::load_server_tls(&cert_path, &key_path, None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        transport::accept(stream, Some(&server_tls)).await
    });
    let client_tls = transport::load_client_tls(
        Some(&wrong_ca_path),
        None,
        Some("localhost"),
        "localhost",
        None,
        None,
    )?;
    assert!(transport::connect("127.0.0.1", port, Some(&client_tls))
        .await
        .is_err());
    let _ = server.await;

    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
    let _ = fs::remove_file(wrong_ca_path);
    Ok(())
}
