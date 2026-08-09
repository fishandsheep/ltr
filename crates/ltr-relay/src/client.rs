//! Client implementation for the LTR service.

use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::{mpsc, Semaphore},
    time::timeout,
};
use tracing::{error, info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::shared::{
    configure_tcp_stream, ClientMessage, Delimited, ServerMessage, CONTROL_PORT, NETWORK_TIMEOUT,
};
use crate::transport::{self, BoxedStream, ClientTlsConfig};

const RECONNECT_MIN_DELAY: Duration = Duration::from_secs(1);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

/// Default cap on concurrent accepted data connections per local tunnel.
pub const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 256;

/// CLI arguments for the local client tunnel.
#[derive(clap::Args, Debug, Clone, Serialize, Deserialize)]
pub struct LocalArgs {
    /// The local port to expose.
    #[arg(env = "LTR_LOCAL_PORT")]
    pub local_port: u16,

    /// The local host to expose.
    #[arg(short, long, value_name = "HOST", default_value = "localhost")]
    pub local_host: String,

    /// Address of the remote server to expose local ports to.
    #[arg(short, long, env = "LTR_SERVER")]
    pub to: String,

    /// Optional port on the remote server to select.
    #[arg(short, long, default_value_t = 0)]
    pub port: u16,

    /// Optional secret for authentication.
    #[arg(short, long, env = "LTR_SECRET", hide_env_values = true)]
    pub secret: Option<String>,

    /// Encrypt control and accepted tunnel connections with TLS.
    #[arg(long)]
    pub tls: bool,

    /// CA PEM used to validate the remote TLS certificate.
    #[arg(long = "tls-ca", env = "LTR_TLS_CA", value_name = "PATH")]
    pub tls_ca: Option<PathBuf>,

    /// SHA-256 fingerprint of the remote TLS certificate.
    #[arg(long = "tls-fingerprint", env = "LTR_TLS_FINGERPRINT")]
    pub tls_fingerprint: Option<String>,

    /// TLS server name; defaults to the --to value.
    #[arg(long = "tls-server-name", env = "LTR_TLS_SERVER_NAME")]
    pub tls_server_name: Option<String>,

    /// Client certificate PEM for mutual tunnel TLS.
    #[arg(
        long = "tls-client-cert",
        env = "LTR_TLS_CLIENT_CERT",
        value_name = "PATH"
    )]
    pub tls_client_cert: Option<PathBuf>,

    /// Client private key PEM for mutual tunnel TLS.
    #[arg(
        long = "tls-client-key",
        env = "LTR_TLS_CLIENT_KEY",
        value_name = "PATH"
    )]
    pub tls_client_key: Option<PathBuf>,

    /// Maximum concurrent data connections for this tunnel.
    #[arg(
        long = "max-connections",
        default_value_t = DEFAULT_MAX_ACTIVE_CONNECTIONS,
        hide = true
    )]
    pub max_connections: usize,
}

/// Events emitted while a local tunnel is running.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelEvent {
    /// A log line for the tunnel.
    Log(String),

    /// Tunnel has started and optionally knows its remote port.
    Started {
        /// Remote port assigned by the server, when known.
        remote_port: Option<u16>,
    },

    /// Tunnel stopped cleanly.
    Stopped,

    /// Tunnel failed with an error message.
    Failed(String),
}

/// State structure for the client.
pub struct Client {
    /// Control connection to the server.
    conn: Option<Delimited<BoxedStream>>,

    /// Destination address of the server.
    to: String,

    // Local host that is forwarded.
    local_host: String,

    /// Local port that is forwarded.
    local_port: u16,

    /// Port that is publicly available on the remote.
    remote_port: u16,

    /// Port requested on reconnect. Zero means reuse the first assigned port.
    requested_port: u16,

    /// Optional secret used to authenticate clients.
    auth: Option<Authenticator>,

    /// Optional event sink for web tunnel management.
    event_tx: Option<mpsc::UnboundedSender<TunnelEvent>>,

    /// Optional TLS transport for control and accept connections.
    tls: Option<ClientTlsConfig>,

    /// Limits concurrent accepted data connections.
    connection_limit: Arc<Semaphore>,
}

struct ClientRuntimeOptions {
    event_tx: Option<mpsc::UnboundedSender<TunnelEvent>>,
    tls: Option<ClientTlsConfig>,
    max_active_connections: usize,
}

impl Client {
    /// Create a new client.
    pub async fn new(
        local_host: &str,
        local_port: u16,
        to: &str,
        port: u16,
        secret: Option<&str>,
    ) -> Result<Self> {
        Self::new_with_events(local_host, local_port, to, port, secret, None).await
    }

    /// Create a new client and emit tunnel events.
    pub async fn new_with_events(
        local_host: &str,
        local_port: u16,
        to: &str,
        port: u16,
        secret: Option<&str>,
        event_tx: Option<mpsc::UnboundedSender<TunnelEvent>>,
    ) -> Result<Self> {
        Self::new_with_events_and_tls(local_host, local_port, to, port, secret, event_tx, None)
            .await
    }

    /// Create a new client with optional TLS and event reporting.
    pub async fn new_with_events_and_tls(
        local_host: &str,
        local_port: u16,
        to: &str,
        port: u16,
        secret: Option<&str>,
        event_tx: Option<mpsc::UnboundedSender<TunnelEvent>>,
        tls: Option<ClientTlsConfig>,
    ) -> Result<Self> {
        Self::new_with_runtime(
            local_host,
            local_port,
            to,
            port,
            secret,
            ClientRuntimeOptions {
                event_tx,
                tls,
                max_active_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
            },
        )
        .await
    }

    async fn new_with_runtime(
        local_host: &str,
        local_port: u16,
        to: &str,
        port: u16,
        secret: Option<&str>,
        options: ClientRuntimeOptions,
    ) -> Result<Self> {
        let ClientRuntimeOptions {
            event_tx,
            tls,
            max_active_connections,
        } = options;
        let auth = secret.map(Authenticator::new);
        let (stream, remote_port) = connect_control(to, port, auth.as_ref(), tls.as_ref()).await?;
        info!(remote_port, "connected to server");
        info!("listening at {to}:{remote_port}");

        let client = Client {
            conn: Some(stream),
            to: to.to_string(),
            local_host: local_host.to_string(),
            local_port,
            remote_port,
            requested_port: port,
            auth,
            event_tx,
            tls,
            connection_limit: Arc::new(Semaphore::new(max_active_connections.max(1))),
        };
        client.emit_log(format!("connected to {to}:{CONTROL_PORT}"));
        client.emit_log(format!("listening at {to}:{remote_port}"));

        Ok(client)
    }

    /// Returns the port publicly available on the remote.
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    /// Start the client, listening for new connections.
    pub async fn listen(self) -> Result<()> {
        self.listen_with_shutdown(std::future::pending::<()>())
            .await
    }

    /// Start the client, listening for new connections until shutdown resolves.
    pub async fn listen_with_shutdown<S>(mut self, shutdown: S) -> Result<()>
    where
        S: Future<Output = ()>,
    {
        let mut conn = Some(self.conn.take().expect("control connection should exist"));
        let this = Arc::new(self);
        let mut reconnect_delay = RECONNECT_MIN_DELAY;
        tokio::pin!(shutdown);

        loop {
            if conn.is_none() {
                let port = this.reconnect_port();
                tokio::select! {
                    _ = &mut shutdown => {
                        this.emit_log("shutdown requested".to_string());
                        return Ok(());
                    }
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }

                match connect_control(&this.to, port, this.auth.as_ref(), this.tls.as_ref()).await {
                    Ok((stream, remote_port)) => {
                        info!(remote_port, "reconnected to server");
                        this.emit_log(format!("reconnected to {}:{CONTROL_PORT}", this.to));
                        if remote_port != this.remote_port {
                            warn!(
                                previous_remote_port = this.remote_port,
                                remote_port, "server returned different remote port"
                            );
                            this.emit_log(format!(
                                "server returned remote port {remote_port}; expected {}",
                                this.remote_port
                            ));
                        }
                        conn = Some(stream);
                        reconnect_delay = RECONNECT_MIN_DELAY;
                    }
                    Err(err) => {
                        warn!(%err, "failed to reconnect to server");
                        this.emit_log(format!("reconnect failed: {err}"));
                        reconnect_delay = next_reconnect_delay(reconnect_delay);
                    }
                }
                continue;
            }

            let control_conn = conn.as_mut().expect("control connection should exist");
            tokio::select! {
                _ = &mut shutdown => {
                    this.emit_log("shutdown requested".to_string());
                    return Ok(());
                }
                message = control_conn.recv() => {
                    match message {
                        Ok(message) => match message {
                        Some(ServerMessage::Hello(_)) => warn!("unexpected hello"),
                        Some(ServerMessage::Challenge(_)) => warn!("unexpected challenge"),
                        Some(ServerMessage::Heartbeat) => (),
                        Some(ServerMessage::Connection(id)) => {
                            let permit = match this.connection_limit.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    this.emit_log(format!(
                                        "connection {id} rejected: active connection limit reached"
                                    ));
                                    continue;
                                }
                            };
                            let this = Arc::clone(&this);
                            tokio::spawn(
                                async move {
                                    info!("new connection");
                                    this.emit_log(format!("accepted remote connection {id}"));
                                    match this.handle_connection(id).await {
                                        Ok(_) => info!("connection exited"),
                                        Err(err) => {
                                            this.emit_log(format!("connection {id} exited with error: {err}"));
                                            warn!(%err, "connection exited with error");
                                        }
                                    }
                                    drop(permit);
                                }
                                .instrument(info_span!("proxy", %id)),
                            );
                        }
                        Some(ServerMessage::Error(err)) => {
                            this.emit_log(format!("server error: {err}"));
                            error!(%err, "server error");
                            conn = None;
                        }
                        None => {
                            warn!("control connection closed");
                            this.emit_log("control connection closed; reconnecting".to_string());
                            conn = None;
                        }
                        },
                        Err(err) => {
                            warn!(%err, "control connection exited with error");
                            this.emit_log(format!("control connection error: {err}; reconnecting"));
                            conn = None;
                        }
                    }
                }
            }
        }
    }

    async fn handle_connection(&self, id: Uuid) -> Result<()> {
        let mut remote_conn =
            Delimited::new(transport::connect(&self.to, CONTROL_PORT, self.tls.as_ref()).await?);
        if let Some(auth) = &self.auth {
            auth.client_handshake(&mut remote_conn).await?;
        }
        remote_conn.send(ClientMessage::Accept(id)).await?;
        let mut local_conn = connect_with_timeout(&self.local_host, self.local_port).await?;
        let mut parts = remote_conn.into_parts();
        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
        local_conn.write_all(&parts.read_buf).await?;
        tokio::io::copy_bidirectional(&mut local_conn, &mut parts.io).await?;
        Ok(())
    }

    fn emit_log(&self, message: String) {
        emit_event(&self.event_tx, TunnelEvent::Log(message));
    }

    fn reconnect_port(&self) -> u16 {
        if self.requested_port == 0 {
            self.remote_port
        } else {
            self.requested_port
        }
    }
}

/// Runs a local tunnel with optional shutdown and event reporting.
pub async fn run_local<S>(
    args: LocalArgs,
    shutdown: S,
    event_tx: Option<mpsc::UnboundedSender<TunnelEvent>>,
) -> Result<()>
where
    S: Future<Output = ()>,
{
    emit_event(
        &event_tx,
        TunnelEvent::Log(format!(
            "starting tunnel {}:{} -> {}:{}",
            args.local_host,
            args.local_port,
            args.to,
            if args.port == 0 {
                "auto".to_string()
            } else {
                args.port.to_string()
            }
        )),
    );

    let tls = if args.tls {
        match transport::load_client_tls(
            args.tls_ca.as_deref(),
            args.tls_fingerprint.as_deref(),
            args.tls_server_name.as_deref(),
            &args.to,
            args.tls_client_cert.as_deref(),
            args.tls_client_key.as_deref(),
        ) {
            Ok(tls) => Some(tls),
            Err(err) => {
                emit_event(&event_tx, TunnelEvent::Failed(err.to_string()));
                return Err(err);
            }
        }
    } else {
        None
    };

    let client = match Client::new_with_runtime(
        &args.local_host,
        args.local_port,
        &args.to,
        args.port,
        args.secret.as_deref(),
        ClientRuntimeOptions {
            event_tx: event_tx.clone(),
            tls,
            max_active_connections: args.max_connections,
        },
    )
    .await
    {
        Ok(client) => client,
        Err(err) => {
            emit_event(&event_tx, TunnelEvent::Failed(err.to_string()));
            return Err(err);
        }
    };

    emit_event(
        &event_tx,
        TunnelEvent::Started {
            remote_port: Some(client.remote_port()),
        },
    );

    if let Err(err) = client.listen_with_shutdown(shutdown).await {
        emit_event(&event_tx, TunnelEvent::Failed(err.to_string()));
        return Err(err);
    }

    emit_event(&event_tx, TunnelEvent::Stopped);
    Ok(())
}

fn emit_event(event_tx: &Option<mpsc::UnboundedSender<TunnelEvent>>, event: TunnelEvent) {
    if let Some(event_tx) = event_tx {
        let _ = event_tx.send(event);
    }
}

async fn connect_with_timeout(to: &str, port: u16) -> Result<TcpStream> {
    let stream = match timeout(NETWORK_TIMEOUT, TcpStream::connect((to, port))).await {
        Ok(res) => res,
        Err(err) => Err(err.into()),
    }
    .with_context(|| format!("could not connect to {to}:{port}"))?;
    configure_tcp_stream(&stream).with_context(|| format!("could not configure {to}:{port}"))?;
    Ok(stream)
}

async fn connect_control(
    to: &str,
    port: u16,
    auth: Option<&Authenticator>,
    tls: Option<&ClientTlsConfig>,
) -> Result<(Delimited<BoxedStream>, u16)> {
    let mut stream = Delimited::new(transport::connect(to, CONTROL_PORT, tls).await?);
    if let Some(auth) = auth {
        auth.client_handshake(&mut stream).await?;
    }

    stream.send(ClientMessage::Hello(port)).await?;
    let remote_port = match stream.recv_timeout().await? {
        Some(ServerMessage::Hello(remote_port)) => remote_port,
        Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
        Some(ServerMessage::Challenge(_)) => {
            bail!("server requires authentication, but no client secret was provided");
        }
        Some(_) => bail!("unexpected initial non-hello message"),
        None => bail!("unexpected EOF"),
    };
    Ok((stream, remote_port))
}

fn next_reconnect_delay(current: Duration) -> Duration {
    std::cmp::min(current * 2, RECONNECT_MAX_DELAY)
}
