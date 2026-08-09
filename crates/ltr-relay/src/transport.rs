//! Plaintext and optional TLS adapters for the shared tunnel control port.
//!
//! The transport interface is deliberately small: callers connect or accept a
//! boxed asynchronous stream, while this module owns TLS negotiation,
//! certificate parsing, and the legacy plaintext fallback.

use std::{
    fs::{self, File},
    io::{BufReader, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use rcgen::generate_simple_self_signed;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::shared::{configure_tcp_stream, NETWORK_TIMEOUT};

/// A stream accepted by the tunnel protocol, either plaintext or TLS-wrapped.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// Erased stream type used by the protocol framing module.
pub type BoxedStream = Box<dyn AsyncStream>;

/// Client-side TLS configuration.
#[derive(Clone)]
pub struct ClientTlsConfig {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

/// Server-side TLS configuration.
#[derive(Clone)]
pub struct ServerTlsConfig {
    acceptor: TlsAcceptor,
}

/// Paths and fingerprint for an automatically generated tunnel certificate.
#[derive(Clone, Debug)]
pub struct ServerTlsMaterial {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub fingerprint: String,
}

/// Build a client TLS configuration from a CA PEM or a SHA-256 certificate fingerprint.
pub fn load_client_tls(
    ca_path: Option<&Path>,
    fingerprint: Option<&str>,
    server_name: Option<&str>,
    fallback_server_name: &str,
    client_cert_path: Option<&Path>,
    client_key_path: Option<&Path>,
) -> Result<ClientTlsConfig> {
    if ca_path.is_some() && fingerprint.is_some() {
        bail!("--tls-ca and --tls-fingerprint cannot be used together");
    }
    if ca_path.is_none() && fingerprint.is_none() {
        bail!("TLS requires --tls-ca or --tls-fingerprint for certificate validation");
    }
    if client_cert_path.is_some() != client_key_path.is_some() {
        bail!("--tls-client-cert and --tls-client-key must be provided together");
    }

    let client_identity = match (client_cert_path, client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            Some((read_certificates(cert_path)?, read_private_key(key_path)?))
        }
        (None, None) => None,
        _ => unreachable!("client certificate pair validated above"),
    };

    let provider = crypto_provider()?;
    let server_name = parse_server_name(server_name.unwrap_or(fallback_server_name))?;
    let client_config = if let Some(ca_path) = ca_path {
        let roots = root_store(ca_path)?;
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots);
        match client_identity {
            Some((cert_chain, key)) => builder
                .with_client_auth_cert(cert_chain, key)
                .context("invalid TLS client certificate or private key")?,
            None => builder.with_no_client_auth(),
        }
    } else {
        let fingerprint = parse_fingerprint(fingerprint.expect("fingerprint checked above"))?;
        let verifier = PinnedServerCertVerifier {
            fingerprint,
            provider: Arc::clone(&provider),
        };
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        match client_identity {
            Some((cert_chain, key)) => builder
                .with_client_auth_cert(cert_chain, key)
                .context("invalid TLS client certificate or private key")?,
            None => builder.with_no_client_auth(),
        }
    };

    Ok(ClientTlsConfig {
        connector: TlsConnector::from(Arc::new(client_config)),
        server_name,
    })
}

/// Build a server TLS configuration from a PEM certificate/key pair.
pub fn load_server_tls(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<ServerTlsConfig> {
    let provider = crypto_provider()?;
    let cert_chain = read_certificates(cert_path)?;
    if cert_chain.is_empty() {
        bail!(
            "TLS certificate file {} contains no certificates",
            cert_path.display()
        );
    }
    let private_key = read_private_key(key_path)?;
    let builder =
        ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?;
    let server_config = if let Some(client_ca_path) = client_ca_path {
        let roots = Arc::new(root_store(client_ca_path)?);
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots, crypto_provider()?)
                .build()
                .context("failed to build TLS client certificate verifier")?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, private_key)
            .context("invalid TLS certificate or private key")?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("invalid TLS certificate or private key")?
    };

    Ok(ServerTlsConfig {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
    })
}

/// Load or generate the persisted server certificate used by ltr server --tls.
pub fn load_or_generate_server_tls(
    client_ca_path: Option<&Path>,
) -> Result<(ServerTlsConfig, ServerTlsMaterial)> {
    let data_dir = default_data_dir()?.join("ltr");
    load_or_generate_server_tls_at(
        &data_dir.join("tunnel-cert.pem"),
        &data_dir.join("tunnel-key.pem"),
        client_ca_path,
    )
}

/// Load or generate server TLS material at explicit paths.
pub fn load_or_generate_server_tls_at(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<(ServerTlsConfig, ServerTlsMaterial)> {
    if cert_path.exists() != key_path.exists() {
        bail!(
            "tunnel TLS certificate state is incomplete; provide both {} and {}",
            cert_path.display(),
            key_path.display()
        );
    }

    if !cert_path.exists() {
        let parent = cert_path
            .parent()
            .context("tunnel TLS certificate path has no parent directory")?;
        fs::create_dir_all(parent).with_context(|| {
            format!("could not create tunnel TLS directory {}", parent.display())
        })?;
        let generated =
            generate_simple_self_signed(vec!["ltr-server".to_string(), "localhost".to_string()])
                .context("could not generate a self-signed tunnel certificate")?;
        fs::write(cert_path, generated.cert.pem()).with_context(|| {
            format!(
                "could not save tunnel TLS certificate {}",
                cert_path.display()
            )
        })?;
        write_private_file(key_path, generated.signing_key.serialize_pem().as_bytes())
            .with_context(|| {
                format!(
                    "could not save tunnel TLS private key {}",
                    key_path.display()
                )
            })?;
    }

    let certificate = read_certificates(cert_path)?
        .into_iter()
        .next()
        .context("tunnel TLS certificate file contains no certificates")?;
    let fingerprint = hex::encode(Sha256::digest(certificate.as_ref()));
    let tls = load_server_tls(cert_path, key_path, client_ca_path)?;
    Ok((
        tls,
        ServerTlsMaterial {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            fingerprint,
        },
    ))
}

/// Connect to a server over plaintext or TLS.
pub async fn connect(to: &str, port: u16, tls: Option<&ClientTlsConfig>) -> Result<BoxedStream> {
    let stream = timeout(NETWORK_TIMEOUT, TcpStream::connect((to, port)))
        .await
        .context("timed out connecting to server")?
        .with_context(|| format!("could not connect to {to}:{port}"))?;
    configure_tcp_stream(&stream).with_context(|| format!("could not configure {to}:{port}"))?;

    match tls {
        Some(tls) => {
            let stream = timeout(
                NETWORK_TIMEOUT,
                tls.connector.connect(tls.server_name.clone(), stream),
            )
            .await
            .context("timed out during TLS handshake")??;
            Ok(Box::new(stream))
        }
        None => Ok(Box::new(stream)),
    }
}

/// Accept a server connection, auto-detecting a TLS ClientHello when TLS is configured.
pub async fn accept(stream: TcpStream, tls: Option<&ServerTlsConfig>) -> Result<BoxedStream> {
    configure_tcp_stream(&stream).context("could not configure control connection")?;
    let Some(tls) = tls else {
        return Ok(Box::new(stream));
    };

    let mut first_byte = [0u8; 1];
    timeout(NETWORK_TIMEOUT, stream.peek(&mut first_byte))
        .await
        .context("timed out waiting for tunnel transport")??;

    if looks_like_tls_record(first_byte[0]) {
        let stream = timeout(NETWORK_TIMEOUT, tls.acceptor.accept(stream))
            .await
            .context("timed out during TLS handshake")??;
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(stream))
    }
}

fn looks_like_tls_record(first_byte: u8) -> bool {
    matches!(first_byte, 20..=23)
}

fn crypto_provider() -> Result<Arc<CryptoProvider>> {
    // Building a rustls config installs the one provider selected by the
    // enabled rustls features. Keeping the provider explicit makes custom
    // certificate verification use the same algorithms as the TLS config.
    let _ = ClientConfig::builder();
    CryptoProvider::get_default()
        .cloned()
        .context("no rustls crypto provider is available")
}

fn parse_server_name(value: &str) -> Result<ServerName<'static>> {
    if value.is_empty() {
        bail!("TLS server name cannot be empty");
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(ServerName::from(ip));
    }
    ServerName::try_from(value.to_owned()).map_err(|_| {
        anyhow::anyhow!("invalid TLS server name {value:?}; use a DNS name or IP address")
    })
}

fn parse_fingerprint(value: &str) -> Result<[u8; 32]> {
    let compact = value.replace([':', '-', ' '], "");
    let bytes = hex::decode(&compact).context("TLS fingerprint must be hexadecimal")?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "TLS fingerprint must contain 32 bytes (64 hex characters), got {}",
            bytes.len()
        )
    })
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("could not read {}", path.display()))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("invalid PEM certificate file {}", path.display()))
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("could not read {}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .context("invalid PEM private key")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "private key file {} contains no private key",
                path.display()
            )
        })
}

fn root_store(path: &Path) -> Result<RootCertStore> {
    let certs = read_certificates(path)?;
    if certs.is_empty() {
        bail!("CA file {} contains no certificates", path.display());
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|err| {
            anyhow::anyhow!("invalid CA certificate in {}: {err}", path.display())
        })?;
    }
    Ok(roots)
}

fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(contents)
}

fn default_data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"));

    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library/Application Support")
            .into_os_string()
    });

    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME").or_else(|| {
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".local/share").into_os_string())
    });

    base.map(PathBuf::from)
        .context("could not determine the user data directory")
}

#[derive(Debug)]
struct PinnedServerCertVerifier {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual = Sha256::digest(end_entity.as_ref());
        if actual.as_slice() != self.fingerprint {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{looks_like_tls_record, parse_fingerprint, parse_server_name};

    #[test]
    fn detects_tls_record_types_without_reclassifying_json() {
        assert!(looks_like_tls_record(22));
        assert!(looks_like_tls_record(23));
        assert!(!looks_like_tls_record(b'{'));
        assert!(!looks_like_tls_record(b'['));
    }

    #[test]
    fn parses_sha256_fingerprint_with_separators() {
        let fingerprint = parse_fingerprint(
            "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f",
        )
        .expect("fingerprint should parse");
        assert_eq!(fingerprint[0], 0);
        assert_eq!(fingerprint[31], 31);
    }

    #[test]
    fn accepts_dns_and_ip_server_names() {
        assert!(parse_server_name("localhost").is_ok());
        assert!(parse_server_name("127.0.0.1").is_ok());
    }
}
