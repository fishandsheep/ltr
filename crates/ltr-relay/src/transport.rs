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
    sync::{Arc, Mutex},
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

/// How long the server waits for the client's first byte before deciding a
/// silent peer is a plaintext client waiting for the authentication
/// challenge. TLS clients send their ClientHello immediately, so only
/// server-speaks-first plaintext flows hit this window.
const PLAINTEXT_QUIET_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

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
    /// Human-readable note set when a TOFU verifier trusts a fingerprint for
    /// the first time, so callers can surface it in logs.
    trust_note: Arc<Mutex<Option<String>>>,
}

impl ClientTlsConfig {
    /// Returns and clears the first-use TOFU trust note, if any.
    pub fn take_trust_note(&self) -> Option<String> {
        self.trust_note.lock().ok().and_then(|mut note| note.take())
    }
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

/// Client TLS trust and identity options.
#[derive(Default)]
pub struct ClientTlsOptions<'a> {
    /// PEM CA used to validate the remote certificate.
    pub ca_path: Option<&'a Path>,
    /// SHA-256 fingerprint pinning the remote certificate.
    pub fingerprint: Option<&'a str>,
    /// TLS server name override; defaults to the `--to` value.
    pub server_name: Option<&'a str>,
    /// Client certificate PEM for mutual TLS.
    pub client_cert_path: Option<&'a Path>,
    /// Client private key PEM for mutual TLS.
    pub client_key_path: Option<&'a Path>,
    /// `host:port` key used by the trust-on-first-use known-hosts store.
    pub tofu_host: &'a str,
    /// Optional override for the known-hosts store path.
    pub tofu_store_path: Option<&'a Path>,
}

/// Build a client TLS configuration from a CA PEM, a SHA-256 certificate
/// fingerprint, or trust-on-first-use against the known-hosts store.
pub fn load_client_tls(
    options: ClientTlsOptions<'_>,
    fallback_server_name: &str,
) -> Result<ClientTlsConfig> {
    let ClientTlsOptions {
        ca_path,
        fingerprint,
        server_name,
        client_cert_path,
        client_key_path,
        tofu_host,
        tofu_store_path,
    } = options;
    if ca_path.is_some() && fingerprint.is_some() {
        bail!("--tls-ca and --tls-fingerprint cannot be used together");
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
    let trust_note = Arc::new(Mutex::new(None));
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let client_config = if let Some(ca_path) = ca_path {
        let roots = root_store(ca_path)?;
        let builder = builder.with_root_certificates(roots);
        match client_identity {
            Some((cert_chain, key)) => builder
                .with_client_auth_cert(cert_chain, key)
                .context("invalid TLS client certificate or private key")?,
            None => builder.with_no_client_auth(),
        }
    } else if let Some(fingerprint) = fingerprint {
        let fingerprint = parse_fingerprint(fingerprint)?;
        let verifier = PinnedServerCertVerifier {
            fingerprint,
            provider: Arc::clone(&provider),
        };
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        match client_identity {
            Some((cert_chain, key)) => builder
                .with_client_auth_cert(cert_chain, key)
                .context("invalid TLS client certificate or private key")?,
            None => builder.with_no_client_auth(),
        }
    } else {
        let store_path = tofu_store_path
            .map(PathBuf::from)
            .unwrap_or_else(default_known_hosts_path);
        let expected = Mutex::new(known_hosts_load(&store_path)?.remove(tofu_host));
        let verifier = TofuServerCertVerifier {
            host: tofu_host.to_string(),
            expected,
            store_path,
            provider: Arc::clone(&provider),
            trust_note: Arc::clone(&trust_note),
        };
        let builder = builder
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
        trust_note,
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
    let stream = tcp_connect(to, port).await?;

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

/// Connect with TLS-first negotiation: try TLS unless the caller already
/// knows the peer is plaintext-only, and fall back to plaintext when the
/// peer clearly does not speak TLS. Certificate-trust failures never fall
/// back; only message-framing errors do.
pub async fn connect_negotiated(
    to: &str,
    port: u16,
    tls: Option<&ClientTlsConfig>,
    plaintext_peer: &std::sync::atomic::AtomicBool,
) -> Result<BoxedStream> {
    let Some(tls) = tls else {
        return connect(to, port, None).await;
    };
    if plaintext_peer.load(std::sync::atomic::Ordering::Relaxed) {
        return connect(to, port, None).await;
    }

    let stream = tcp_connect(to, port).await?;
    match timeout(
        NETWORK_TIMEOUT,
        tls.connector.connect(tls.server_name.clone(), stream),
    )
    .await
    .context("timed out during TLS handshake")?
    {
        Ok(stream) => Ok(Box::new(stream)),
        Err(err) if is_non_tls_peer_error(&err) => {
            // The latch is process-wide and permanent: once a peer proves
            // itself non-TLS, later connections skip TLS entirely. Say so —
            // a silent permanent downgrade deserves a log line.
            tracing::warn!(
                error = %err,
                "peer is not speaking TLS; falling back to plaintext for this process"
            );
            plaintext_peer.store(true, std::sync::atomic::Ordering::Relaxed);
            connect(to, port, None).await
        }
        Err(err) => Err(err).context("TLS handshake failed"),
    }
}

/// True when a TLS handshake error indicates the peer responded with
/// non-TLS bytes (or closed the connection), rather than a trust failure.
fn is_non_tls_peer_error(err: &std::io::Error) -> bool {
    fn chain_has_framing_error(start: &(dyn std::error::Error + 'static)) -> bool {
        let mut source = Some(start);
        while let Some(current) = source {
            // Framing errors mean the peer answered with non-TLS bytes; trust
            // failures (certificate errors) must NOT fall back to plaintext.
            if let Some(rustls_err) = current.downcast_ref::<rustls::Error>() {
                if matches!(rustls_err, rustls::Error::InvalidMessage(_)) {
                    return true;
                }
            }
            source = current.source();
        }
        false
    }

    // tokio-rustls wraps the rustls error as the io::Error's inner payload;
    // io::Error::source() skips over the inner error itself, so inspect
    // get_ref() explicitly before walking the source chain.
    if let Some(inner) = err.get_ref() {
        let inner: &(dyn std::error::Error + 'static) = inner;
        if chain_has_framing_error(inner) {
            return true;
        }
    }
    chain_has_framing_error(err) || matches!(err.kind(), std::io::ErrorKind::UnexpectedEof)
}

async fn tcp_connect(to: &str, port: u16) -> Result<TcpStream> {
    let stream = timeout(NETWORK_TIMEOUT, TcpStream::connect((to, port)))
        .await
        .context("timed out connecting to server")?
        .with_context(|| format!("could not connect to {to}:{port}"))?;
    configure_tcp_stream(&stream).with_context(|| format!("could not configure {to}:{port}"))?;
    Ok(stream)
}

/// Accept a server connection, auto-detecting a TLS ClientHello when TLS is
/// configured. A peer that stays silent for the quiet window is treated as
/// a plaintext client waiting for the server to speak first (the HMAC
/// challenge flow), which repairs plaintext authentication over a
/// TLS-enabled control port.
pub async fn accept(stream: TcpStream, tls: Option<&ServerTlsConfig>) -> Result<BoxedStream> {
    configure_tcp_stream(&stream).context("could not configure control connection")?;
    let Some(tls) = tls else {
        return Ok(Box::new(stream));
    };

    let mut first_byte = [0u8; 1];
    let peeked = timeout(PLAINTEXT_QUIET_WINDOW, stream.peek(&mut first_byte)).await;
    match peeked {
        // A byte arrived: classify TLS vs plaintext by record type.
        Ok(Ok(_)) => {}
        // Quiet window elapsed: treat as a plaintext peer waiting for the
        // server to speak first.
        Err(_elapsed) => {
            return Ok(Box::new(stream));
        }
        Ok(Err(err)) => return Err(err).context("could not inspect tunnel transport"),
    }

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

fn default_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"));

    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library/Application Support")
            .into_os_string()
    });

    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_CONFIG_HOME").or_else(|| {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config").into_os_string())
    });

    base.map(|base| PathBuf::from(base).join("ltr"))
        .context("could not determine the user config directory")
}

/// Default path of the trust-on-first-use known-hosts store.
pub fn default_known_hosts_path() -> PathBuf {
    default_config_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("known_hosts")
}

/// Load the known-hosts store as `host:port -> sha256 fingerprint` pairs.
fn known_hosts_load(path: &Path) -> Result<std::collections::HashMap<String, [u8; 32]>> {
    let mut hosts = std::collections::HashMap::new();
    let Ok(contents) = fs::read_to_string(path) else {
        return Ok(hosts);
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((host, fingerprint)) = line.split_once(' ') else {
            continue;
        };
        if let Ok(fingerprint) = parse_fingerprint(fingerprint) {
            hosts.insert(host.to_string(), fingerprint);
        }
    }
    Ok(hosts)
}

/// Record a trusted fingerprint for one host, keeping other entries intact.
fn known_hosts_store(path: &Path, host: &str, fingerprint: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create config directory {}", parent.display()))?;
    }
    let mut hosts = known_hosts_load(path)?;
    hosts.insert(host.to_string(), *fingerprint);
    let mut keys: Vec<String> = hosts.keys().cloned().collect();
    keys.sort();
    let mut lines = String::from("# ltr known hosts: host sha256-fingerprint\n");
    for key in keys {
        let fp = hosts.get(&key).expect("key just inserted");
        let hexfp: String = fp.iter().map(|byte| format!("{byte:02x}")).collect();
        lines.push_str(&format!("{key} {hexfp}\n"));
    }
    let tmp_path = path.with_extension("tmp");
    write_private_file(&tmp_path, lines.as_bytes())
        .with_context(|| format!("could not write {}", tmp_path.display()))?;
    // Atomic replace: a concurrent reader or a crash must never observe a
    // half-written store (which would silently reset TOFU trust).
    fs::rename(&tmp_path, path).with_context(|| format!("could not replace {}", path.display()))
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

#[derive(Debug)]
struct TofuServerCertVerifier {
    host: String,
    /// Fingerprint trusted for this host: loaded from the store at startup
    /// and updated in memory on first use. The cache is what pins later
    /// handshakes in this process (reconnects, new data connections) — the
    /// shared `ClientConfig` never rebuilds, so a stale `None` here would
    /// re-trust every new certificate.
    expected: Mutex<Option<[u8; 32]>>,
    store_path: PathBuf,
    provider: Arc<CryptoProvider>,
    trust_note: Arc<Mutex<Option<String>>>,
}

impl TofuServerCertVerifier {
    fn fingerprint_mismatch_error(&self, expected: [u8; 32], actual: &str) -> rustls::Error {
        // The guidance mirrors SSH's known_hosts reset flow; there is no
        // skip-verification escape hatch.
        let note = format!(
            "certificate fingerprint mismatch for {}: expected {}, got {}. If you trust the new \
             certificate, remove the matching line from {} and reconnect",
            self.host,
            expected
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            actual,
            self.store_path.display()
        );
        if let Ok(mut slot) = self.trust_note.lock() {
            *slot = Some(note);
        }
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    }
}

impl ServerCertVerifier for TofuServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        let mut expected = self
            .expected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *expected {
            Some(expected_fingerprint) if expected_fingerprint != actual => {
                let hex = actual
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                Err(self.fingerprint_mismatch_error(expected_fingerprint, &hex))
            }
            Some(_) => Ok(ServerCertVerified::assertion()),
            None => {
                // First use: persist the fingerprint, then pin it in memory so
                // every later handshake in this process compares against it.
                if let Err(err) = known_hosts_store(&self.store_path, &self.host, &actual) {
                    return Err(rustls::Error::General(format!(
                        "could not persist trusted fingerprint: {err}"
                    )));
                }
                *expected = Some(actual);
                let hex = actual
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                if let Ok(mut slot) = self.trust_note.lock() {
                    *slot = Some(format!(
                        "first connection to {}: trusted and saved certificate fingerprint {hex}",
                        self.host
                    ));
                }
                Ok(ServerCertVerified::assertion())
            }
        }
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
