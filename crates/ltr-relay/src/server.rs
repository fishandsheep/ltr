//! Server implementation for the LTR service.

use std::net::{IpAddr, Ipv4Addr};
use std::{io, ops::RangeInclusive, sync::Arc, sync::Mutex, time::Duration};

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{sleep, timeout},
};
use tracing::{info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::shared::{configure_tcp_stream, ClientMessage, Delimited, ServerMessage, CONTROL_PORT};
use crate::transport::{self, BoxedStream, ServerTlsConfig};
use crate::OnReady;

const MAX_CONTROL_CONNECTIONS: usize = 1024;
const MAX_PENDING_CONNECTIONS: usize = 1024;

/// State structure for the server.
pub struct Server {
    /// Range of TCP ports that can be forwarded.
    port_range: RangeInclusive<u16>,

    /// Optional secret used to authenticate clients.
    auth: Option<Authenticator>,

    /// Pending data sockets indexed by protocol connection ID.
    conns: Arc<DashMap<Uuid, (TcpStream, OwnedSemaphorePermit)>>,
    pending_connection_limit: Arc<Semaphore>,
    control_connection_limit: Arc<Semaphore>,

    /// IP address where the control server will bind to.
    bind_addr: IpAddr,

    /// IP address where tunnels will listen on.
    bind_tunnels: IpAddr,

    /// Optional TLS adapter for the shared control port.
    tls: Option<ServerTlsConfig>,

    /// Optional callback fired once the control listener is bound.
    on_ready: Option<Mutex<OnReady>>,
}

impl Server {
    /// Create a new server with a specified minimum port number.
    pub fn new(port_range: RangeInclusive<u16>, secret: Option<&str>) -> Self {
        assert!(!port_range.is_empty(), "must provide at least one port");
        Server {
            port_range,
            conns: Arc::new(DashMap::new()),
            pending_connection_limit: Arc::new(Semaphore::new(MAX_PENDING_CONNECTIONS)),
            control_connection_limit: Arc::new(Semaphore::new(MAX_CONTROL_CONNECTIONS)),
            auth: secret.map(Authenticator::new),
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_tunnels: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            tls: None,
            on_ready: None,
        }
    }

    /// Set the IP address where the control server will bind.
    pub fn set_bind_addr(&mut self, bind_addr: IpAddr) {
        self.bind_addr = bind_addr;
    }

    /// Set the IP address where public tunnel listeners will bind.
    pub fn set_bind_tunnels(&mut self, bind_tunnels: IpAddr) {
        self.bind_tunnels = bind_tunnels;
    }

    /// Enable optional TLS while preserving plaintext auto-detection.
    pub fn set_tls(&mut self, tls: ServerTlsConfig) {
        self.tls = Some(tls);
    }

    /// Set a callback fired once the control listener is bound and the
    /// server enters its accept loop.
    pub fn set_on_ready(&mut self, on_ready: OnReady) {
        self.on_ready = Some(Mutex::new(on_ready));
    }

    /// Start the server, listening for new connections.
    pub async fn listen(mut self) -> Result<()> {
        let on_ready = self
            .on_ready
            .take()
            .map(Mutex::into_inner)
            .map(|on_ready| on_ready.expect("on-ready lock should not be poisoned"));
        let this = Arc::new(self);
        let listener = TcpListener::bind((this.bind_addr, CONTROL_PORT)).await?;
        info!(addr = ?this.bind_addr, "server listening");
        if this.auth.is_none() {
            warn!("server authentication is disabled; use --secret for a restricted relay");
        }
        if let Some(on_ready) = on_ready {
            on_ready();
        }

        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    warn!(%err, "failed to accept control connection; retrying");
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let permit = match Arc::clone(&this.control_connection_limit).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!(?addr, "control connection limit reached");
                    drop(stream);
                    continue;
                }
            };
            let this = Arc::clone(&this);
            tokio::spawn(
                async move {
                    let _permit = permit;
                    info!("incoming connection");
                    let stream = match transport::accept(stream, this.tls.as_ref()).await {
                        Ok(stream) => stream,
                        Err(err) => {
                            warn!(%err, "transport handshake failed");
                            return;
                        }
                    };
                    if let Err(err) = this.handle_connection(stream).await {
                        warn!(%err, "connection exited with error");
                    } else {
                        info!("connection exited");
                    }
                }
                .instrument(info_span!("control", ?addr)),
            );
        }
    }

    async fn create_listener(&self, port: u16) -> Result<TcpListener, &'static str> {
        let try_bind = |port: u16| async move {
            TcpListener::bind((self.bind_tunnels, port))
                .await
                .map_err(|err| match err.kind() {
                    io::ErrorKind::AddrInUse => "port already in use",
                    io::ErrorKind::PermissionDenied => "permission denied",
                    _ => "failed to bind to port",
                })
        };
        // Client requests a specific port number outside the allowed range.
        if port > 0 && !self.port_range.contains(&port) {
            return Err("client port number not in allowed range");
        }
        // When a specific port turns out to be occupied, fall back to a random
        // available port; the assigned port is reported back through the Hello
        // message so the client can surface the change.
        if port > 0 {
            match try_bind(port).await {
                Ok(listener) => return Ok(listener),
                Err("port already in use") => {}
                Err(err) => return Err(err),
            }
        }
        // Bind to 150 random port numbers. We choose this value because in
        // order to find a free port with probability at least 1-δ, when ε proportion
        // of the ports are currently available, it suffices to check approximately -2 ln(δ) / ε
        // independently and uniformly chosen ports (up to a second-order term in ε).
        //
        // Checking 150 times gives us 99.999% success at utilizing 85% of ports under these
        // conditions, when ε=0.15 and δ=0.00001.
        for _ in 0..150 {
            let port = fastrand::u16(self.port_range.clone());
            match try_bind(port).await {
                Ok(listener) => return Ok(listener),
                Err(_) => continue,
            }
        }
        Err("failed to find an available port")
    }

    async fn handle_connection(&self, stream: BoxedStream) -> Result<()> {
        let mut stream = Delimited::new(stream);
        if let Some(auth) = &self.auth {
            if let Err(err) = auth.server_handshake(&mut stream).await {
                warn!(%err, "server handshake failed");
                stream.send(ServerMessage::Error(err.to_string())).await?;
                return Ok(());
            }
        }

        match stream.recv_timeout().await? {
            Some(ClientMessage::Authenticate(_)) => {
                warn!("unexpected authenticate");
                Ok(())
            }
            Some(ClientMessage::Hello(port)) => {
                let listener = match self.create_listener(port).await {
                    Ok(listener) => listener,
                    Err(err) => {
                        stream.send(ServerMessage::Error(err.into())).await?;
                        return Ok(());
                    }
                };
                let host = listener.local_addr()?.ip();
                let port = listener.local_addr()?.port();
                info!(?host, ?port, "new client");
                stream.send(ServerMessage::Hello(port)).await?;

                loop {
                    if stream.send(ServerMessage::Heartbeat).await.is_err() {
                        // Assume that the TCP connection has been dropped.
                        return Ok(());
                    }
                    const TIMEOUT: Duration = Duration::from_millis(500);
                    let accepted = match timeout(TIMEOUT, listener.accept()).await {
                        Ok(Ok(accepted)) => Some(accepted),
                        Ok(Err(err)) => {
                            warn!(%err, "failed to accept tunnel connection; retrying");
                            sleep(Duration::from_millis(100)).await;
                            None
                        }
                        Err(_) => None,
                    };
                    if let Some((stream2, addr)) = accepted {
                        let permit =
                            match Arc::clone(&self.pending_connection_limit).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!(?addr, "pending tunnel connection limit reached");
                                    drop(stream2);
                                    continue;
                                }
                            };
                        if let Err(err) = configure_tcp_stream(&stream2) {
                            warn!(%err, "failed to configure proxy connection");
                        }
                        info!(?addr, ?port, "new connection");

                        let id = Uuid::new_v4();
                        let conns = Arc::clone(&self.conns);

                        conns.insert(id, (stream2, permit));
                        tokio::spawn(async move {
                            // Remove stale entries to avoid memory leaks.
                            sleep(Duration::from_secs(10)).await;
                            if conns.remove(&id).is_some() {
                                warn!(%id, "removed stale connection");
                            }
                        });
                        stream.send(ServerMessage::Connection(id)).await?;
                    }
                }
            }
            Some(ClientMessage::Accept(id)) => {
                info!(%id, "forwarding connection");
                match self.conns.remove(&id) {
                    Some((_, (mut stream2, _permit))) => {
                        let mut parts = stream.into_parts();
                        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
                        stream2.write_all(&parts.read_buf).await?;
                        tokio::io::copy_bidirectional(&mut parts.io, &mut stream2).await?;
                    }
                    None => warn!(%id, "missing connection"),
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
