#![allow(missing_docs)]

use std::{
    env,
    ffi::OsString,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use clap::{error::ErrorKind, ArgAction, CommandFactory, Parser, Subcommand};
use tokio::sync::{mpsc, oneshot};

use crate::{
    client::{run_local, LocalArgs, TunnelEvent, DEFAULT_MAX_ACTIVE_CONNECTIONS},
    daemon,
    server::Server,
    shared::CONTROL_PORT,
    transport,
    web::{
        self, credentials, OnReady, SessionInfo, SessionMode, SystemTunnelRole, SystemTunnelSpec,
        TunnelConfig, WebLimits, WebState,
    },
};

const WEB_RISK_WARNING: &str =
    "Warning: remote Web access is public. Keep the bearer token private and protect the HTTPS endpoint.";

/// Default remote port for the exposed web console (`ltr web`).
const DEFAULT_WEB_PORT: u16 = 7836;

/// Default remote port for the exposed SSH tunnel (`ltr ssh`).
const SSH_DEFAULT_REMOTE_PORT: u16 = 2222;

const AFTER_HELP: &str = "Examples:\n  ltr 8000 -t your-server.example\n  ltr 8000\n  ltr 192.168.1.5:8000 -t your-server.example -p 9000\n  ltr web\n  ltr ssh\n  ltr server\n  ltr -l\n  ltr -s 9000";

/// Shared local web console arguments, flattened into every mode that hosts the console.
#[derive(clap::Args, Debug, Clone)]
pub struct WebConsoleArgs {
    /// Address for the local web console.
    #[arg(long = "web-addr", default_value = "127.0.0.1:7836", hide = true)]
    pub web_addr: SocketAddr,

    /// Bearer token for Web API requests.
    #[arg(
        long = "web-token",
        env = "LTR_WEB_TOKEN",
        hide_env_values = true,
        hide = true
    )]
    pub web_token: Option<String>,

    /// Maximum number of tunnel definitions in the Web control plane.
    #[arg(
        long = "web-max-tunnels",
        env = "LTR_WEB_MAX_TUNNELS",
        default_value_t = 64,
        hide = true
    )]
    pub web_max_tunnels: usize,

    /// Maximum active data connections per Web-managed tunnel.
    #[arg(
        long = "web-max-connections",
        env = "LTR_WEB_MAX_CONNECTIONS",
        default_value_t = 256,
        hide = true
    )]
    pub web_max_connections: usize,

    /// Maximum retained log lines per Web-managed tunnel.
    #[arg(
        long = "web-max-log-lines",
        env = "LTR_WEB_MAX_LOG_LINES",
        default_value_t = 500,
        hide = true
    )]
    pub web_max_log_lines: usize,
}

/// Shared relay destination arguments, flattened at the top level and into the
/// tunnel subcommands so both `ltr 8000 -t host` and `ltr web -t host` work.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct TunnelArgs {
    /// Address of the remote relay server.
    #[arg(short = 't', long = "to", env = "LTR_SERVER", value_name = "HOST")]
    pub to: Option<String>,

    /// Remote port to request on the relay; 0 asks for a free port.
    #[arg(short = 'p', long = "dport", value_name = "PORT")]
    pub dport: Option<u16>,

    /// Optional secret for authentication.
    #[arg(
        long = "secret",
        env = "LTR_SECRET",
        hide_env_values = true,
        hide = true
    )]
    pub secret: Option<String>,

    /// Disable TLS and connect over plaintext (for relays without TLS).
    #[arg(long = "no-tls", action = ArgAction::SetTrue, hide = true)]
    pub no_tls: bool,

    /// CA PEM used to validate the remote TLS certificate.
    #[arg(long = "tls-ca", env = "LTR_TLS_CA", value_name = "PATH", hide = true)]
    pub tls_ca: Option<PathBuf>,

    /// SHA-256 fingerprint of the remote TLS certificate.
    #[arg(long = "tls-fingerprint", env = "LTR_TLS_FINGERPRINT", hide = true)]
    pub tls_fingerprint: Option<String>,

    /// TLS server name; defaults to the --to value.
    #[arg(long = "tls-server-name", env = "LTR_TLS_SERVER_NAME", hide = true)]
    pub tls_server_name: Option<String>,

    /// Client certificate PEM for mutual tunnel TLS.
    #[arg(
        long = "tls-client-cert",
        env = "LTR_TLS_CLIENT_CERT",
        value_name = "PATH",
        hide = true
    )]
    pub tls_client_cert: Option<PathBuf>,

    /// Client private key PEM for mutual tunnel TLS.
    #[arg(
        long = "tls-client-key",
        env = "LTR_TLS_CLIENT_KEY",
        value_name = "PATH",
        hide = true
    )]
    pub tls_client_key: Option<PathBuf>,

    /// Maximum concurrent data connections for this tunnel.
    #[arg(long = "max-connections", hide = true)]
    pub max_connections: Option<usize>,
}

impl TunnelArgs {
    /// Merges two layers of tunnel arguments; the subcommand layer wins.
    pub fn merged_over(&self, top: &TunnelArgs) -> TunnelArgs {
        let pick = |sub: Option<String>, top: Option<String>| sub.or(top);
        TunnelArgs {
            to: pick(self.to.clone(), top.to.clone()),
            dport: self.dport.or(top.dport),
            secret: pick(self.secret.clone(), top.secret.clone()),
            no_tls: self.no_tls || top.no_tls,
            tls_ca: self.tls_ca.clone().or(top.tls_ca.clone()),
            tls_fingerprint: pick(self.tls_fingerprint.clone(), top.tls_fingerprint.clone()),
            tls_server_name: pick(self.tls_server_name.clone(), top.tls_server_name.clone()),
            tls_client_cert: self.tls_client_cert.clone().or(top.tls_client_cert.clone()),
            tls_client_key: self.tls_client_key.clone().or(top.tls_client_key.clone()),
            max_connections: self.max_connections.or(top.max_connections),
        }
    }
}

/// Top-level CLI arguments.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    disable_version_flag = true,
    disable_help_subcommand = true,
    override_usage = "ltr [COMMAND] [OPTIONS]",
    after_help = AFTER_HELP
)]
pub struct Args {
    /// Local endpoint to expose: a bare port ("8000") or "host:port".
    #[arg(value_name = "[HOST:]PORT", value_parser = local_target_value)]
    pub target: Option<String>,

    #[command(flatten)]
    pub tunnel: TunnelArgs,

    /// Keep running in the foreground; by default LTR moves to the background
    /// after printing its startup summary.
    #[arg(short = 'f', long = "front", env = "LTR_FRONT", action = ArgAction::SetTrue)]
    pub front: bool,

    /// List exposed ports from running LTR instances.
    #[arg(short = 'l', long = "list", action = ArgAction::SetTrue)]
    pub list: bool,

    /// Stop a running instance by its exposed port; interactive when omitted.
    #[arg(short = 's', long = "stop", value_name = "PORT", num_args = 0..=1)]
    pub stop: Option<Option<u16>>,

    /// Prints version information.
    #[arg(short = 'v', long = "version", action = ArgAction::Version, hide = true)]
    pub version: Option<bool>,

    #[command(flatten)]
    pub web: WebConsoleArgs,

    /// Log filter, for example info or ltr_cli=debug.
    #[arg(
        long = "log-level",
        env = "LTR_LOG_LEVEL",
        default_value = "info",
        hide = true
    )]
    pub log_level: String,

    /// Emit structured JSON logs instead of human-readable logs.
    #[arg(
        long = "log-json",
        env = "LTR_LOG_JSON",
        default_value_t = false,
        hide = true
    )]
    pub log_json: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Parses CLI arguments.
pub fn parse_args() -> Args {
    parse_args_from(env::args_os())
}

/// Initialize logging from parsed CLI and environment settings.
pub fn init_logging(args: &Args) {
    init_logging_into(args, None);
}

/// Initialize logging, optionally appending to a log file instead of writing
/// to the terminal (background mode).
pub fn init_logging_into(args: &Args, file: Option<daemon::LogFileWriter>) {
    let filter = tracing_subscriber::EnvFilter::try_new(&args.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match (args.log_json, file) {
        (true, Some(writer)) => builder.json().with_writer(writer).init(),
        (true, None) => builder.json().init(),
        (false, Some(writer)) => builder.with_writer(writer).init(),
        (false, None) => builder.init(),
    }
}

/// Parses an argument iterator.
pub fn parse_args_from<I, T>(args: I) -> Args
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Args::parse_from(args)
}

/// Top-level command variants.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Exposes the web console through a remote relay.
    Web(WebArgs),

    /// Exposes local SSH through a remote relay.
    Ssh(SshArgs),

    /// Runs the LTR relay server.
    Server(ServerArgs),
}

/// Remote web console CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct WebArgs {
    #[command(flatten)]
    pub tunnel: TunnelArgs,

    /// PEM certificate for remote Web HTTPS.
    #[arg(long = "web-cert", value_name = "PATH", hide = true)]
    pub web_cert: Option<PathBuf>,

    /// PEM private key for remote Web HTTPS.
    #[arg(long = "web-key", value_name = "PATH", hide = true)]
    pub web_key: Option<PathBuf>,
}

/// Remote SSH tunnel CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct SshArgs {
    #[command(flatten)]
    pub tunnel: TunnelArgs,

    /// Local SSH endpoint to forward (port or host:port).
    #[arg(long = "ssh-local", value_name = "[HOST:]PORT", hide = true)]
    pub ssh_local: Option<String>,
}

/// Server CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct ServerArgs {
    /// Minimum accepted TCP port number.
    #[arg(long, default_value_t = 1024, env = "LTR_MIN_PORT", hide = true)]
    pub min_port: u16,

    /// Maximum accepted TCP port number.
    #[arg(long, default_value_t = 65535, env = "LTR_MAX_PORT", hide = true)]
    pub max_port: u16,

    /// Optional secret for authentication.
    #[arg(
        short = 'S',
        long,
        env = "LTR_SECRET",
        hide_env_values = true,
        hide = true
    )]
    pub secret: Option<String>,

    /// IP address to bind to, clients must reach this.
    #[arg(long, default_value = "0.0.0.0", hide = true)]
    pub bind_addr: IpAddr,

    /// IP address where tunnels will listen on, defaults to --bind-addr.
    #[arg(long, hide = true)]
    pub bind_tunnels: Option<IpAddr>,

    /// Disable tunnel TLS. TLS is enabled by default with a generated certificate.
    #[arg(
        long = "no-tls",
        env = "LTR_NO_TLS",
        action = ArgAction::SetTrue,
        hide = true
    )]
    pub no_tls: bool,

    /// PEM certificate overriding the default generated tunnel certificate.
    #[arg(
        long = "tls-cert",
        env = "LTR_TLS_CERT",
        value_name = "PATH",
        hide = true
    )]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key used by optional tunnel TLS.
    #[arg(
        long = "tls-key",
        env = "LTR_TLS_KEY",
        value_name = "PATH",
        hide = true
    )]
    pub tls_key: Option<PathBuf>,

    /// CA PEM used to require client certificates during tunnel TLS.
    #[arg(
        long = "tls-client-ca",
        env = "LTR_TLS_CLIENT_CA",
        value_name = "PATH",
        hide = true
    )]
    pub tls_client_ca: Option<PathBuf>,
}

/// Parses a local endpoint: a bare port means 127.0.0.1.
pub fn parse_local_target(target: &str) -> Result<(String, u16)> {
    let target = target.trim();
    if target.is_empty() {
        bail!("the local endpoint is empty; expected a port like 8000 or host:port like 127.0.0.1:8000");
    }
    if let Ok(port) = target.parse::<u16>() {
        return Ok(("127.0.0.1".to_string(), port));
    }
    match target.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port: u16 = port.parse().with_context(|| {
                format!("invalid port in local endpoint {target:?}; expected [HOST:]PORT")
            })?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            Ok((host.to_string(), port))
        }
        _ => bail!(
            "invalid local endpoint {target:?}; expected a port like 8000 or host:port like 127.0.0.1:8000"
        ),
    }
}

/// Value parser for the positional endpoint: validates the form at parse time
/// while keeping the raw string.
fn local_target_value(value: &str) -> Result<String, String> {
    parse_local_target(value)
        .map(|_| value.to_string())
        .map_err(|err| format!("{err:#}"))
}

/// Returns the relay address or fails with actionable guidance.
pub fn require_to(to: Option<&str>) -> Result<String> {
    match to.map(str::trim).filter(|to| !to.is_empty()) {
        Some(to) => Ok(to.to_string()),
        None => bail!(
            "no relay server configured for this tunnel.\n\n\
             Specify one now:\n  ltr 8000 -t your-server.example\n\n\
             Or save a default:\n  ltr conf set to your-server.example\n\n\
             The LTR_SERVER environment variable is also respected."
        ),
    }
}

/// Validates a layer of tunnel arguments.
fn validate_tunnel_args(tunnel: &TunnelArgs, cmd: &mut clap::Command) -> Result<(), clap::Error> {
    if tunnel.no_tls
        && (tunnel.tls_ca.is_some()
            || tunnel.tls_fingerprint.is_some()
            || tunnel.tls_server_name.is_some()
            || tunnel.tls_client_cert.is_some()
            || tunnel.tls_client_key.is_some())
    {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--tls-ca, --tls-fingerprint, --tls-server-name, --tls-client-cert, and --tls-client-key cannot be used with --no-tls",
        ));
    }
    if tunnel.tls_client_cert.is_some() != tunnel.tls_client_key.is_some() {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--tls-client-cert and --tls-client-key must be provided together",
        ));
    }
    Ok(())
}

/// Validates parsed CLI arguments.
pub fn validate_args(args: &Args) -> std::result::Result<(), clap::Error> {
    let mut cmd = Args::command();
    if args.target.is_some() && args.command.is_some() {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "choose either a [HOST:]PORT or a subcommand, not both",
        ));
    }
    validate_tunnel_args(&args.tunnel, &mut cmd)?;
    match &args.command {
        Some(Command::Web(web_args)) => {
            if !args.web.web_addr.ip().is_loopback() {
                return Err(cmd.error(
                    ErrorKind::InvalidValue,
                    "web mode requires --web-addr to bind to loopback",
                ));
            }
            if web_args.web_cert.is_some() != web_args.web_key.is_some() {
                return Err(cmd.error(
                    ErrorKind::InvalidValue,
                    "--web-cert and --web-key must be provided together",
                ));
            }
            validate_tunnel_args(&web_args.tunnel, &mut cmd)?;
        }
        Some(Command::Ssh(ssh_args)) => {
            validate_tunnel_args(&ssh_args.tunnel, &mut cmd)?;
        }
        Some(Command::Server(server_args)) => {
            if server_args.tls_cert.is_some() != server_args.tls_key.is_some() {
                return Err(cmd.error(
                    ErrorKind::InvalidValue,
                    "--tls-cert and --tls-key must be provided together",
                ));
            }
            if server_args.tls_client_ca.is_some() && server_args.no_tls {
                return Err(cmd.error(
                    ErrorKind::InvalidValue,
                    "--tls-client-ca cannot be used with --no-tls",
                ));
            }
            if server_args.no_tls
                && (server_args.tls_cert.is_some() || server_args.tls_key.is_some())
            {
                return Err(cmd.error(
                    ErrorKind::InvalidValue,
                    "--tls-cert and --tls-key cannot be used with --no-tls",
                ));
            }
        }
        None => {}
    }
    Ok(())
}

/// Creates the ready hook that prints the background summary once a mode
/// finishes startup, carrying optional extra summary lines. In foreground
/// mode the hook fires too, but the summary is a no-op.
fn daemon_ready_hook(extra_lines: Vec<String>) -> OnReady {
    let (ready_tx, ready_rx) = oneshot::channel::<Vec<String>>();
    daemon::spawn_finish(ready_rx);
    Box::new(move || {
        let _ = ready_tx.send(extra_lines);
    })
}

/// Runs parsed CLI command.
pub async fn run(args: Args) -> Result<()> {
    if let Err(err) = validate_args(&args) {
        err.exit();
    }

    if args.list || args.stop.is_some() {
        // Instance management (list/stop) arrives with the instance registry.
        bail!("listing and stopping running instances is not available yet");
    }

    match (&args.command, args.target.as_deref()) {
        (Some(Command::Server(server_args)), _) => {
            let port_range = server_args.min_port..=server_args.max_port;
            if port_range.is_empty() {
                Args::command()
                    .error(ErrorKind::InvalidValue, "port range is empty")
                    .exit();
            }
            let bind_addr = server_args.bind_addr;
            let mut server = Server::new(port_range, server_args.secret.as_deref());
            server.set_bind_addr(server_args.bind_addr);
            server.set_bind_tunnels(server_args.bind_tunnels.unwrap_or(server_args.bind_addr));
            let (ready_tx, ready_rx) = oneshot::channel::<Vec<String>>();
            daemon::spawn_finish(ready_rx);
            server.set_on_ready(Box::new(move || {
                let _ = ready_tx.send(vec![format!(
                    "LTR server listening on {bind_addr}:{CONTROL_PORT}"
                )]);
            }));
            if !server_args.no_tls {
                let tls = match (&server_args.tls_cert, &server_args.tls_key) {
                    (Some(cert), Some(key)) => {
                        transport::load_server_tls(cert, key, server_args.tls_client_ca.as_deref())?
                    }
                    (None, None) => {
                        let (tls, material) = transport::load_or_generate_server_tls(
                            server_args.tls_client_ca.as_deref(),
                        )?;
                        println!(
                            "Tunnel TLS certificate stored at: {}",
                            material.cert_path.display()
                        );
                        println!(
                            "Tunnel TLS private key stored at: {}",
                            material.key_path.display()
                        );
                        println!("Tunnel TLS SHA-256 fingerprint: {}", material.fingerprint);
                        tls
                    }
                    _ => unreachable!("server TLS certificate pair validated above"),
                };
                server.set_tls(tls);
            }
            server.listen().await?;
        }
        (Some(Command::Web(web_args)), _) => {
            run_web_remote(&args, web_args).await?;
        }
        (Some(Command::Ssh(ssh_args)), _) => {
            let tunnel = ssh_args.tunnel.merged_over(&args.tunnel);
            let (local_host, local_port) =
                parse_local_target(ssh_args.ssh_local.as_deref().unwrap_or("22"))?;
            let to = require_to(tunnel.to.as_deref())?;
            let local_args =
                build_local_args(&tunnel, local_host, local_port, to, SSH_DEFAULT_REMOTE_PORT);
            run_tunnel(local_args, "LTR ssh tunnel").await?;
        }
        (None, Some(target)) => {
            let (local_host, local_port) = parse_local_target(target)?;
            let to = require_to(args.tunnel.to.as_deref())?;
            let local_args = build_local_args(&args.tunnel, local_host, local_port, to, 0);
            run_tunnel(local_args, "LTR local tunnel").await?;
        }
        (None, None) => {
            return run_web_local(
                args.web.web_addr,
                args.web.web_token,
                web_limits(
                    args.web.web_max_tunnels,
                    args.web.web_max_connections,
                    args.web.web_max_log_lines,
                ),
                Some(daemon_ready_hook(Vec::new())),
            )
            .await;
        }
    }

    Ok(())
}

/// Builds library-level tunnel arguments from the resolved CLI layer.
fn build_local_args(
    tunnel: &TunnelArgs,
    local_host: String,
    local_port: u16,
    to: String,
    default_port: u16,
) -> LocalArgs {
    LocalArgs {
        local_port,
        local_host,
        to,
        port: tunnel.dport.unwrap_or(default_port),
        secret: tunnel.secret.clone(),
        no_tls: tunnel.no_tls,
        tls_ca: tunnel.tls_ca.clone(),
        tls_fingerprint: tunnel.tls_fingerprint.clone(),
        tls_server_name: tunnel.tls_server_name.clone(),
        tls_client_cert: tunnel.tls_client_cert.clone(),
        tls_client_key: tunnel.tls_client_key.clone(),
        max_connections: tunnel
            .max_connections
            .unwrap_or(DEFAULT_MAX_ACTIVE_CONNECTIONS),
    }
}

/// Runs a plain local tunnel with the background ready hook wired to the
/// first `Started` event, which carries the assigned remote port.
async fn run_tunnel(local_args: LocalArgs, label: &str) -> Result<()> {
    let (ready_tx, ready_rx) = oneshot::channel::<Vec<String>>();
    daemon::spawn_finish(ready_rx);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let to = local_args.to.clone();
    let local_host = local_args.local_host.clone();
    let local_port = local_args.local_port;
    let requested_port = local_args.port;
    let label = label.to_string();
    tokio::spawn(async move {
        while let Some(event) = events_rx.recv().await {
            if let TunnelEvent::Started {
                remote_port: Some(remote_port),
            } = event
            {
                // The relay reassigns occupied ports; surface the change so the
                // requested port is never silently missing.
                if requested_port != 0 && remote_port != requested_port {
                    println!(
                        "Remote port {requested_port} is already in use; using {remote_port} instead"
                    );
                }
                let _ = ready_tx.send(vec![format!(
                    "{label}: {local_host}:{local_port} -> {to}:{remote_port}"
                )]);
                break;
            }
        }
    });
    run_local(
        local_args,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        Some(events_tx),
    )
    .await
}

fn web_limits(
    max_tunnels: usize,
    max_active_connections: usize,
    max_log_lines: usize,
) -> WebLimits {
    WebLimits {
        max_tunnels,
        max_active_connections,
        max_log_lines,
    }
}

fn report_generated_web_credentials(
    token_was_generated: bool,
    certificate_was_generated: bool,
) -> Result<()> {
    if token_was_generated {
        let path = credentials::web_token_path()?;
        println!("Web bearer token stored at: {}", path.display());
        println!("Read the token from: {}", path.display());
    }
    if certificate_was_generated {
        let (cert_path, key_path) = credentials::web_tls_paths()?;
        println!("Web HTTPS certificate stored at: {}", cert_path.display());
        println!("Web HTTPS private key stored at: {}", key_path.display());
    }
    Ok(())
}

pub async fn run_web_local(
    web_addr: SocketAddr,
    web_token: Option<String>,
    limits: WebLimits,
    on_ready: Option<OnReady>,
) -> Result<()> {
    if !web_addr.ip().is_loopback() && web_token.is_none() {
        eprintln!(
            "Warning: Web console is exposed on a non-loopback address without Web authentication."
        );
    }
    let state = WebState::with_limits_and_store(
        SessionInfo::local(),
        web_token,
        None,
        limits,
        Some(web::default_tunnels_path()),
    );
    web::serve_with_state_on_ready(
        web::ServeConfig {
            addr: web_addr,
            session: state.session().await,
        },
        state,
        tokio::signal::ctrl_c(),
        on_ready,
    )
    .await
}

/// Exposes the local web console through a remote relay (`ltr web`).
pub async fn run_web_remote(args: &Args, web_args: &WebArgs) -> Result<()> {
    let tunnel = web_args.tunnel.merged_over(&args.tunnel);
    let to = require_to(tunnel.to.as_deref())?;
    let remote_port = tunnel.dport.unwrap_or(DEFAULT_WEB_PORT);
    let session = SessionInfo {
        mode: SessionMode::RemoteWeb,
        warnings: vec![WEB_RISK_WARNING.to_string()],
        loopback_only: true,
        web_remote_url: Some(format!("https://{to}:{remote_port}")),
        ssh_remote_endpoint: None,
    };
    let token_was_generated = args.web.web_token.is_none();
    let certificate_was_generated = web_args.web_cert.is_none();
    let web_token = credentials::load_or_generate(args.web.web_token.clone())?;
    let web_tls = credentials::load_or_generate_tls(
        &to,
        web_args.web_cert.as_deref(),
        web_args.web_key.as_deref(),
    )?;
    let state = WebState::with_limits_and_store(
        session,
        Some(web_token.clone()),
        Some(web_tls),
        web_limits(
            args.web.web_max_tunnels,
            args.web.web_max_connections,
            args.web.web_max_log_lines,
        ),
        Some(web::default_tunnels_path()),
    );
    report_generated_web_credentials(token_was_generated, certificate_was_generated)?;
    let system_tunnels = vec![SystemTunnelSpec {
        role: SystemTunnelRole::WebConsole,
        config: TunnelConfig {
            name: "Web Console".to_string(),
            local_port: args.web.web_addr.port(),
            to: to.clone(),
            port: Some(remote_port),
            local_host: "127.0.0.1".to_string(),
            secret: tunnel.secret.clone(),
        },
        display_url: Some(format!("https://{to}:{remote_port}")),
    }];
    web::run_managed_on_ready(
        web::ServeConfig {
            addr: args.web.web_addr,
            session: state.session().await,
        },
        state,
        system_tunnels,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        Some(daemon_ready_hook(Vec::new())),
    )
    .await
}

#[cfg(test)]
mod tests {
    use clap::{error::ErrorKind, CommandFactory, Parser};

    use super::{
        parse_local_target, require_to, validate_args, Args, Command, WebArgs, DEFAULT_WEB_PORT,
        SSH_DEFAULT_REMOTE_PORT,
    };

    #[test]
    fn zero_args_start_local_web_console() {
        let args = Args::try_parse_from(["ltr"]).expect("parse should succeed");
        assert!(args.command.is_none());
        assert!(args.target.is_none());
        assert!(!args.front);
        assert_eq!(args.web.web_addr.to_string(), "127.0.0.1:7836");
    }

    #[test]
    fn parse_bare_port_target() {
        let args = Args::try_parse_from(["ltr", "8000"]).expect("parse should succeed");
        assert_eq!(args.target.as_deref(), Some("8000"));
        assert!(args.command.is_none());
    }

    #[test]
    fn parse_host_port_target_with_tunnel_flags() {
        let args =
            Args::try_parse_from(["ltr", "192.168.1.5:8000", "-t", "example.com", "-p", "9000"])
                .expect("parse should succeed");
        assert_eq!(args.target.as_deref(), Some("192.168.1.5:8000"));
        assert_eq!(args.tunnel.to.as_deref(), Some("example.com"));
        assert_eq!(args.tunnel.dport, Some(9000));
    }

    #[test]
    fn parse_list_and_stop_flags() {
        let args = Args::try_parse_from(["ltr", "-l"]).expect("parse should succeed");
        assert!(args.list);

        let args = Args::try_parse_from(["ltr", "-s"]).expect("parse should succeed");
        assert_eq!(args.stop, Some(None));

        let args = Args::try_parse_from(["ltr", "-s", "9000"]).expect("parse should succeed");
        assert_eq!(args.stop, Some(Some(9000)));

        let args = Args::try_parse_from(["ltr", "--stop", "9000"]).expect("parse should succeed");
        assert_eq!(args.stop, Some(Some(9000)));

        let args = Args::try_parse_from(["ltr"]).expect("parse should succeed");
        assert_eq!(args.stop, None);
    }

    #[test]
    fn parse_front_flag() {
        let args = Args::try_parse_from(["ltr", "--front"]).expect("parse should succeed");
        assert!(args.front);

        let args = Args::try_parse_from(["ltr", "-f", "8000"]).expect("parse should succeed");
        assert!(args.front);
        assert_eq!(args.target.as_deref(), Some("8000"));
    }

    #[test]
    fn removed_subcommand_words_reject_as_invalid_endpoints() {
        for word in ["help", "local", "bundle"] {
            let err =
                Args::try_parse_from(["ltr", word]).expect_err("bare words are not subcommands");
            assert_eq!(err.kind(), ErrorKind::ValueValidation, "word: {word}");
        }
    }

    #[test]
    fn web_subcommand_parses_with_tunnel_flags_after_it() {
        let args = Args::try_parse_from(["ltr", "web", "-t", "example.com", "-p", "9000"])
            .expect("parse should succeed");
        let Some(Command::Web(WebArgs { tunnel, .. })) = &args.command else {
            panic!("expected web command");
        };
        assert_eq!(tunnel.to.as_deref(), Some("example.com"));
        assert_eq!(tunnel.dport, Some(9000));
    }

    #[test]
    fn ssh_subcommand_parses_with_defaults() {
        let args = Args::try_parse_from(["ltr", "ssh", "-t", "example.com"])
            .expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Ssh(_))));
    }

    #[test]
    fn top_level_tunnel_flags_reach_web_mode() {
        let args = Args::try_parse_from(["ltr", "-t", "top.example", "web"])
            .expect("parse should succeed");
        let Some(Command::Web(web_args)) = &args.command else {
            panic!("expected web command");
        };
        let merged = web_args.tunnel.merged_over(&args.tunnel);
        assert_eq!(merged.to.as_deref(), Some("top.example"));

        let args = Args::try_parse_from(["ltr", "-t", "top.example", "web", "-t", "sub.example"])
            .expect("parse should succeed");
        let Some(Command::Web(web_args)) = &args.command else {
            panic!("expected web command");
        };
        let merged = web_args.tunnel.merged_over(&args.tunnel);
        assert_eq!(merged.to.as_deref(), Some("sub.example"));
    }

    #[test]
    fn usage_line_shows_command_before_options() {
        let help = Args::command().render_help().to_string();
        assert!(help.contains("Usage: ltr [COMMAND] [OPTIONS]"));
    }

    #[test]
    fn help_shows_only_core_flags() {
        let help = Args::command().render_help().to_string();
        for core in [
            "-t, --to",
            "-p, --dport",
            "-f, --front",
            "-l, --list",
            "-s, --stop",
        ] {
            assert!(help.contains(core), "help should show {core}");
        }
        for hidden in [
            "--secret",
            "--log-level",
            "--log-json",
            "--web-addr",
            "--web-token",
            "--no-tls",
            "--tls-ca",
            "-v, --version",
        ] {
            assert!(!help.contains(hidden), "help should not show {hidden}");
        }
    }

    #[test]
    fn help_mentions_new_examples() {
        let help = Args::command().render_long_help().to_string();
        assert!(help.contains("ltr 8000 -t your-server.example"));
        assert!(help.contains("ltr web"));
        assert!(help.contains("ltr ssh"));
        assert!(!help.contains("npx @qinshower/ltr"));
    }

    #[test]
    fn parse_version_short_flag() {
        let err = Args::try_parse_from(["ltr", "-v"]).expect_err("version should exit");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn parse_logging_options() {
        let args = Args::try_parse_from(["ltr", "--log-level", "debug", "--log-json", "server"])
            .expect("parse should succeed");
        assert_eq!(args.log_level, "debug");
        assert!(args.log_json);
    }

    #[test]
    fn parse_server_no_tls_flag() {
        let args =
            Args::try_parse_from(["ltr", "server", "--no-tls"]).expect("parse should succeed");
        let Some(Command::Server(server)) = args.command else {
            panic!("expected server command");
        };
        assert!(server.no_tls);
    }

    #[test]
    fn target_and_subcommand_are_mutually_exclusive() {
        let args = Args::try_parse_from(["ltr", "8000", "server"]).expect("parse should succeed");
        let err = validate_args(&args).expect_err("validation should fail");
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn web_requires_loopback_addr() {
        let args = Args::try_parse_from(["ltr", "--web-addr", "0.0.0.0:7836", "web", "-t", "host"])
            .expect("parse should succeed");
        let err = validate_args(&args).expect_err("validation should fail");
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn tunnel_tls_conflicts_are_rejected() {
        let args = Args::try_parse_from(["ltr", "8000", "-t", "h", "--no-tls", "--tls-ca", "/a"])
            .expect("parse should succeed");
        let err = validate_args(&args).expect_err("validation should fail");
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn parse_local_target_forms() {
        assert_eq!(
            parse_local_target("8000").unwrap(),
            ("127.0.0.1".to_string(), 8000)
        );
        assert_eq!(
            parse_local_target("127.0.0.1:8000").unwrap(),
            ("127.0.0.1".to_string(), 8000)
        );
        assert_eq!(
            parse_local_target("localhost:22").unwrap(),
            ("localhost".to_string(), 22)
        );
        assert_eq!(
            parse_local_target("[::1]:22").unwrap(),
            ("::1".to_string(), 22)
        );
        assert!(parse_local_target("8000:").is_err());
        assert!(parse_local_target("host").is_err());
        assert!(parse_local_target("").is_err());
        assert!(parse_local_target("a:b").is_err());
    }

    #[test]
    fn require_to_error_is_actionable() {
        let err = require_to(None).expect_err("missing to should fail");
        let message = format!("{err:#}");
        assert!(message.contains("ltr conf set to"));
        assert!(message.contains("LTR_SERVER"));
        assert_eq!(require_to(Some(" example.com ")).unwrap(), "example.com");
    }

    #[test]
    fn web_port_constants() {
        assert_eq!(super::DEFAULT_WEB_PORT, 7836);
        assert_eq!(super::SSH_DEFAULT_REMOTE_PORT, 2222);
    }
}
