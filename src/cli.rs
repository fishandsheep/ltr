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
    conf::{self, FileConfig},
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

const AFTER_HELP: &str = "Examples:\n  ltr 8000 -t your-server.example\n  ltr 8000\n  ltr 192.168.1.5:8000 -t your-server.example -p 9000\n  ltr web\n  ltr ssh\n  ltr server\n  ltr -l\n  ltr -s 9000\n  ltr conf set to your-server.example";

/// Shared local web console arguments (all hidden power flags; the defaults
/// live in the conf registry).
#[derive(clap::Args, Debug, Clone, Default)]
pub struct WebConsoleArgs {
    /// Address for the local web console.
    #[arg(long = "web-addr", hide = true)]
    pub web_addr: Option<SocketAddr>,

    /// Bearer token for Web API requests.
    #[arg(long = "web-token", hide = true)]
    pub web_token: Option<String>,

    /// Maximum number of tunnel definitions in the Web control plane.
    #[arg(long = "web-max-tunnels", hide = true)]
    pub web_max_tunnels: Option<usize>,

    /// Maximum active data connections per Web-managed tunnel.
    #[arg(long = "web-max-connections", hide = true)]
    pub web_max_connections: Option<usize>,

    /// Maximum retained log lines per Web-managed tunnel.
    #[arg(long = "web-max-log-lines", hide = true)]
    pub web_max_log_lines: Option<usize>,
}

/// Shared relay destination arguments, flattened at the top level and into the
/// tunnel subcommands so both `ltr 8000 -t host` and `ltr web -t host` work.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct TunnelArgs {
    /// Address of the remote relay server.
    #[arg(short = 't', long = "to", value_name = "HOST")]
    pub to: Option<String>,

    /// Remote port to request on the relay; 0 asks for a free port.
    #[arg(short = 'p', long = "dport", value_name = "PORT")]
    pub dport: Option<u16>,

    /// Optional secret for authentication.
    #[arg(long = "secret", hide = true)]
    pub secret: Option<String>,

    /// Disable TLS and connect over plaintext (for relays without TLS).
    #[arg(long = "no-tls", action = ArgAction::SetTrue, hide = true)]
    pub no_tls: bool,

    /// CA PEM used to validate the remote TLS certificate.
    #[arg(long = "tls-ca", value_name = "PATH", hide = true)]
    pub tls_ca: Option<PathBuf>,

    /// SHA-256 fingerprint of the remote TLS certificate.
    #[arg(long = "tls-fingerprint", hide = true)]
    pub tls_fingerprint: Option<String>,

    /// TLS server name; defaults to the --to value.
    #[arg(long = "tls-server-name", hide = true)]
    pub tls_server_name: Option<String>,

    /// Client certificate PEM for mutual tunnel TLS.
    #[arg(long = "tls-client-cert", value_name = "PATH", hide = true)]
    pub tls_client_cert: Option<PathBuf>,

    /// Client private key PEM for mutual tunnel TLS.
    #[arg(long = "tls-client-key", value_name = "PATH", hide = true)]
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

/// Top-level CLI arguments. Every optional field stays `Option` so the conf
/// layer can tell "explicitly passed" apart from "unset".
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
    #[arg(short = 'f', long = "front", action = ArgAction::SetTrue)]
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
    #[arg(long = "log-level", hide = true)]
    pub log_level: Option<String>,

    /// Emit structured JSON logs instead of human-readable logs.
    #[arg(long = "log-json", action = ArgAction::SetTrue, hide = true)]
    pub log_json: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Args {
    /// Returns true for quick one-shot commands that never daemonize.
    pub fn is_quick(&self) -> bool {
        self.list
            || self.stop.is_some()
            || matches!(self.command, Some(Command::Conf(_)))
    }
}

/// Parses CLI arguments.
pub fn parse_args() -> Args {
    parse_args_from(env::args_os())
}

/// Initialize logging with resolved settings.
pub fn init_logging(log_level: &str, log_json: bool) {
    init_logging_into(log_level, log_json, None);
}

/// Initialize logging, optionally appending to a log file instead of writing
/// to the terminal (background mode).
pub fn init_logging_into(
    log_level: &str,
    log_json: bool,
    file: Option<daemon::LogFileWriter>,
) {
    let filter = tracing_subscriber::EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match (log_json, file) {
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

    /// Manages the persistent configuration file.
    Conf(ConfArgs),

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

/// Configuration management CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct ConfArgs {
    #[command(subcommand)]
    pub action: ConfAction,
}

/// `ltr conf` sub-actions.
#[derive(Subcommand, Debug, Clone)]
pub enum ConfAction {
    /// Shows all settings, or one key with its value and source.
    Get { key: Option<String> },

    /// Saves a setting to the config file.
    Set { key: String, value: String },

    /// Removes a setting from the config file.
    Unset { key: String },
}

/// Server CLI arguments.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct ServerArgs {
    /// Minimum accepted TCP port number.
    #[arg(long, hide = true)]
    pub min_port: Option<u16>,

    /// Maximum accepted TCP port number.
    #[arg(long, hide = true)]
    pub max_port: Option<u16>,

    /// Optional secret for authentication.
    #[arg(long, hide = true)]
    pub secret: Option<String>,

    /// IP address to bind to, clients must reach this.
    #[arg(long, hide = true)]
    pub bind_addr: Option<IpAddr>,

    /// IP address where tunnels will listen on, defaults to --bind-addr.
    #[arg(long, hide = true)]
    pub bind_tunnels: Option<IpAddr>,

    /// Disable tunnel TLS. TLS is enabled by default with a generated certificate.
    #[arg(long = "no-tls", action = ArgAction::SetTrue, hide = true)]
    pub no_tls: bool,

    /// PEM certificate overriding the default generated tunnel certificate.
    #[arg(long = "tls-cert", value_name = "PATH", hide = true)]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key used by optional tunnel TLS.
    #[arg(long = "tls-key", value_name = "PATH", hide = true)]
    pub tls_key: Option<PathBuf>,

    /// CA PEM used to require client certificates during tunnel TLS.
    #[arg(long = "tls-client-ca", value_name = "PATH", hide = true)]
    pub tls_client_ca: Option<PathBuf>,
}

/// Fully resolved settings for one invocation: CLI > config file > `LTR_*`
/// environment variables > built-in defaults.
#[derive(Debug, Clone)]
pub struct Eff {
    /// Remote relay server.
    pub to: Option<String>,
    /// Remote port to request, when pinned.
    pub dport: Option<u16>,
    /// Shared authentication secret.
    pub secret: Option<String>,
    /// Whether TLS is disabled.
    pub no_tls: bool,
    /// CA PEM for relay TLS validation.
    pub tls_ca: Option<PathBuf>,
    /// SHA-256 fingerprint for relay TLS validation.
    pub tls_fingerprint: Option<String>,
    /// TLS server name override.
    pub tls_server_name: Option<String>,
    /// Client certificate PEM for mutual tunnel TLS.
    pub tls_client_cert: Option<PathBuf>,
    /// Client private key PEM for mutual tunnel TLS.
    pub tls_client_key: Option<PathBuf>,
    /// Maximum concurrent data connections for CLI tunnels.
    pub max_connections: usize,
    /// Whether the command stays in the foreground.
    pub front: bool,
    /// Log filter.
    pub log_level: String,
    /// Whether logs are structured JSON.
    pub log_json: bool,
    /// Local web console bind address.
    pub web_addr: SocketAddr,
    /// Web console bearer token.
    pub web_token: Option<String>,
    /// Web console tunnel limit.
    pub web_max_tunnels: usize,
    /// Web console per-tunnel connection limit.
    pub web_max_connections: usize,
    /// Web console retained log lines.
    pub web_max_log_lines: usize,
    /// PEM certificate for remote Web HTTPS.
    pub web_cert: Option<PathBuf>,
    /// PEM private key for remote Web HTTPS.
    pub web_key: Option<PathBuf>,
    /// Local SSH endpoint for `ltr ssh`.
    pub ssh_local: Option<String>,
    /// Server: minimum accepted tunnel port.
    pub min_port: u16,
    /// Server: maximum accepted tunnel port.
    pub max_port: u16,
    /// Server: control bind address.
    pub bind_addr: IpAddr,
    /// Server: tunnel listener address override.
    pub bind_tunnels: Option<IpAddr>,
    /// Server: PEM certificate override for tunnel TLS.
    pub tls_cert: Option<PathBuf>,
    /// Server: PEM private key for tunnel TLS.
    pub tls_key: Option<PathBuf>,
    /// Server: CA PEM requiring client certificates.
    pub tls_client_ca: Option<PathBuf>,
}

impl Eff {
    /// Resolves every setting from the CLI layers, the config file, the
    /// environment, and the registry defaults.
    pub fn resolve(args: &Args, file: &FileConfig) -> Self {
        let tunnel = match &args.command {
            Some(Command::Web(web)) => web.tunnel.merged_over(&args.tunnel),
            Some(Command::Ssh(ssh)) => ssh.tunnel.merged_over(&args.tunnel),
            _ => args.tunnel.clone(),
        };
        let (web_cert, web_key) = match &args.command {
            Some(Command::Web(web)) => (web.web_cert.clone(), web.web_key.clone()),
            _ => (None, None),
        };
        let ssh_local = match &args.command {
            Some(Command::Ssh(ssh)) => ssh.ssh_local.clone(),
            _ => None,
        };
        let server = match &args.command {
            Some(Command::Server(server)) => server.clone(),
            _ => ServerArgs::default(),
        };
        Self {
            to: conf::layered_str("to", tunnel.to, file),
            dport: conf::layered_u16("dport", tunnel.dport, file),
            secret: conf::layered_str("secret", tunnel.secret, file),
            no_tls: conf::layered_flag("no-tls", tunnel.no_tls, file).unwrap_or(false),
            tls_ca: conf::layered_path("tls-ca", tunnel.tls_ca, file),
            tls_fingerprint: conf::layered_str("tls-fingerprint", tunnel.tls_fingerprint, file),
            tls_server_name: conf::layered_str(
                "tls-server-name",
                tunnel.tls_server_name,
                file,
            ),
            tls_client_cert: conf::layered_path(
                "tls-client-cert",
                tunnel.tls_client_cert,
                file,
            ),
            tls_client_key: conf::layered_path("tls-client-key", tunnel.tls_client_key, file),
            max_connections: conf::layered_usize(
                "max-connections",
                tunnel.max_connections,
                file,
            )
            .unwrap_or(DEFAULT_MAX_ACTIVE_CONNECTIONS),
            front: conf::layered_flag("front", args.front, file).unwrap_or(false),
            log_level: conf::layered_str("log-level", args.log_level.clone(), file)
                .unwrap_or_else(|| "info".to_string()),
            log_json: conf::layered_flag("log-json", args.log_json, file).unwrap_or(false),
            web_addr: conf::layered_addr("web-addr", args.web.web_addr, file)
                .unwrap_or_else(|| "127.0.0.1:7836".parse().expect("default web addr")),
            web_token: conf::layered_str("web-token", args.web.web_token.clone(), file),
            web_max_tunnels: conf::layered_usize(
                "web-max-tunnels",
                args.web.web_max_tunnels,
                file,
            )
            .unwrap_or(64),
            web_max_connections: conf::layered_usize(
                "web-max-connections",
                args.web.web_max_connections,
                file,
            )
            .unwrap_or(256),
            web_max_log_lines: conf::layered_usize(
                "web-max-log-lines",
                args.web.web_max_log_lines,
                file,
            )
            .unwrap_or(500),
            web_cert: conf::layered_path("web-cert", web_cert, file),
            web_key: conf::layered_path("web-key", web_key, file),
            ssh_local: conf::layered_str("ssh-local", ssh_local, file),
            min_port: conf::layered_u16("min-port", server.min_port, file).unwrap_or(1024),
            max_port: conf::layered_u16("max-port", server.max_port, file).unwrap_or(65535),
            bind_addr: conf::layered_ip("bind-addr", server.bind_addr, file)
                .unwrap_or(IpAddr::from([0, 0, 0, 0])),
            bind_tunnels: conf::layered_ip("bind-tunnels", server.bind_tunnels, file),
            tls_cert: conf::layered_path("tls-cert", server.tls_cert, file),
            tls_key: conf::layered_path("tls-key", server.tls_key, file),
            tls_client_ca: conf::layered_path("tls-client-ca", server.tls_client_ca, file),
        }
    }
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
pub fn require_to(eff: &Eff) -> Result<String> {
    match eff.to.as_deref().map(str::trim).filter(|to| !to.is_empty()) {
        Some(to) => Ok(to.to_string()),
        None => bail!(
            "no relay server configured for this tunnel.\n\n\
             Specify one now:\n  ltr 8000 -t your-server.example\n\n\
             Or save a default:\n  ltr conf set to your-server.example\n\n\
             Checked in order: command line, config file ({}), LTR_SERVER.",
            FileConfig::path().display()
        ),
    }
}

/// Validates the resolved invocation.
pub fn validate(args: &Args, eff: &Eff) -> std::result::Result<(), clap::Error> {
    let mut cmd = Args::command();
    if args.target.is_some() && args.command.is_some() {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "choose either a [HOST:]PORT or a subcommand, not both",
        ));
    }
    if eff.no_tls
        && (eff.tls_ca.is_some()
            || eff.tls_fingerprint.is_some()
            || eff.tls_server_name.is_some()
            || eff.tls_client_cert.is_some()
            || eff.tls_client_key.is_some())
    {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--tls-ca, --tls-fingerprint, --tls-server-name, --tls-client-cert, and --tls-client-key cannot be used with --no-tls",
        ));
    }
    if eff.tls_client_cert.is_some() != eff.tls_client_key.is_some() {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--tls-client-cert and --tls-client-key must be provided together",
        ));
    }
    if eff.web_cert.is_some() != eff.web_key.is_some() {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--web-cert and --web-key must be provided together",
        ));
    }
    if eff.tls_cert.is_some() != eff.tls_key.is_some() {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--tls-cert and --tls-key must be provided together",
        ));
    }
    if eff.tls_client_ca.is_some() && eff.no_tls {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--tls-client-ca cannot be used with --no-tls",
        ));
    }
    if eff.no_tls && (eff.tls_cert.is_some() || eff.tls_key.is_some()) {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "--tls-cert and --tls-key cannot be used with --no-tls",
        ));
    }
    if matches!(args.command, Some(Command::Web(_))) && !eff.web_addr.ip().is_loopback() {
        return Err(cmd.error(
            ErrorKind::InvalidValue,
            "web mode requires --web-addr to bind to loopback",
        ));
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

/// Runs parsed CLI command with fully resolved settings.
pub async fn run(args: Args, eff: Eff) -> Result<()> {
    if let Err(err) = validate(&args, &eff) {
        err.exit();
    }

    if args.list || args.stop.is_some() {
        // Instance management (list/stop) arrives with the instance registry.
        bail!("listing and stopping running instances is not available yet");
    }

    match &args.command {
        Some(Command::Conf(conf_args)) => run_conf(conf_args).await,
        Some(Command::Server(_)) => run_server(&eff).await,
        Some(Command::Web(_)) => run_web_remote(&eff).await,
        Some(Command::Ssh(_)) => {
            let (local_host, local_port) =
                parse_local_target(eff.ssh_local.as_deref().unwrap_or("22"))?;
            let to = require_to(&eff)?;
            let local_args =
                build_local_args(&eff, local_host, local_port, to, SSH_DEFAULT_REMOTE_PORT);
            run_tunnel(local_args, "LTR ssh tunnel").await
        }
        None => match args.target.as_deref() {
            Some(target) => {
                let (local_host, local_port) = parse_local_target(target)?;
                let to = require_to(&eff)?;
                let local_args = build_local_args(&eff, local_host, local_port, to, 0);
                run_tunnel(local_args, "LTR local tunnel").await
            }
            None => {
                run_web_local(
                    eff.web_addr,
                    eff.web_token.clone(),
                    web_limits(
                        eff.web_max_tunnels,
                        eff.web_max_connections,
                        eff.web_max_log_lines,
                    ),
                    Some(daemon_ready_hook(Vec::new())),
                )
                .await
            }
        },
    }
}

/// Runs the `ltr conf` sub-actions: get, set, unset.
async fn run_conf(conf_args: &ConfArgs) -> Result<()> {
    match &conf_args.action {
        ConfAction::Get { key } => {
            let file = FileConfig::load()?;
            match key {
                Some(key) => {
                    let spec = conf::key_spec(key).ok_or_else(|| {
                        anyhow::anyhow!(
                            "unknown config key {key:?}; run `ltr conf get` to list valid keys"
                        )
                    })?;
                    match conf::resolve_below_cli(key, &file) {
                        Some(resolved) => println!(
                            "{key} = {}   (from {})",
                            resolved.value, resolved.source
                        ),
                        None => println!("{key} = (not set)"),
                    }
                    println!("# {}", spec.help);
                }
                None => {
                    println!("Config file: {}", FileConfig::path().display());
                    println!(
                        "{:<KEY$} {:<VALUE$} {:<SOURCE$} DESCRIPTION",
                        "KEY",
                        "VALUE",
                        "SOURCE",
                        KEY = 18,
                        VALUE = 28,
                        SOURCE = 7
                    );
                    for spec in conf::KEYS {
                        let resolved = conf::resolve_below_cli(spec.name, &file);
                        match resolved {
                            Some(resolved) => println!(
                                "{:<18} {:<28} {:<7} {}",
                                spec.name, resolved.value, resolved.source, spec.help
                            ),
                            None => println!(
                                "{:<18} {:<28} {:<7} {}",
                                spec.name, "-", "-", spec.help
                            ),
                        }
                    }
                }
            }
            Ok(())
        }
        ConfAction::Set { key, value } => {
            let mut file = FileConfig::load()?;
            file.set(key, value)?;
            file.save()?;
            println!(
                "{} = {value}   (saved to {})",
                key,
                FileConfig::path().display()
            );
            Ok(())
        }
        ConfAction::Unset { key } => {
            let mut file = FileConfig::load()?;
            file.unset(key)?;
            file.save()?;
            println!("{key} unset   ({})", FileConfig::path().display());
            Ok(())
        }
    }
}

/// Runs the relay server.
async fn run_server(eff: &Eff) -> Result<()> {
    let port_range = eff.min_port..=eff.max_port;
    if port_range.is_empty() {
        Args::command()
            .error(ErrorKind::InvalidValue, "port range is empty")
            .exit();
    }
    let bind_addr = eff.bind_addr;
    let mut server = Server::new(port_range, eff.secret.as_deref());
    server.set_bind_addr(eff.bind_addr);
    server.set_bind_tunnels(eff.bind_tunnels.unwrap_or(eff.bind_addr));
    let (ready_tx, ready_rx) = oneshot::channel::<Vec<String>>();
    daemon::spawn_finish(ready_rx);
    server.set_on_ready(Box::new(move || {
        let _ = ready_tx.send(vec![format!(
            "LTR server listening on {bind_addr}:{CONTROL_PORT}"
        )]);
    }));
    if !eff.no_tls {
        let tls = match (&eff.tls_cert, &eff.tls_key) {
            (Some(cert), Some(key)) => {
                transport::load_server_tls(cert, key, eff.tls_client_ca.as_deref())?
            }
            (None, None) => {
                let (tls, material) =
                    transport::load_or_generate_server_tls(eff.tls_client_ca.as_deref())?;
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
    server.listen().await
}

/// Builds library-level tunnel arguments from resolved settings.
fn build_local_args(
    eff: &Eff,
    local_host: String,
    local_port: u16,
    to: String,
    default_port: u16,
) -> LocalArgs {
    LocalArgs {
        local_port,
        local_host,
        to,
        port: eff.dport.unwrap_or(default_port),
        secret: eff.secret.clone(),
        no_tls: eff.no_tls,
        tls_ca: eff.tls_ca.clone(),
        tls_fingerprint: eff.tls_fingerprint.clone(),
        tls_server_name: eff.tls_server_name.clone(),
        tls_client_cert: eff.tls_client_cert.clone(),
        tls_client_key: eff.tls_client_key.clone(),
        max_connections: eff.max_connections,
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
pub async fn run_web_remote(eff: &Eff) -> Result<()> {
    let to = require_to(eff)?;
    let remote_port = eff.dport.unwrap_or(DEFAULT_WEB_PORT);
    let session = SessionInfo {
        mode: SessionMode::RemoteWeb,
        warnings: vec![WEB_RISK_WARNING.to_string()],
        loopback_only: true,
        web_remote_url: Some(format!("https://{to}:{remote_port}")),
        ssh_remote_endpoint: None,
    };
    let token_was_generated = eff.web_token.is_none();
    let certificate_was_generated = eff.web_cert.is_none();
    let web_token = credentials::load_or_generate(eff.web_token.clone())?;
    let web_tls = credentials::load_or_generate_tls(
        &to,
        eff.web_cert.as_deref(),
        eff.web_key.as_deref(),
    )?;
    let state = WebState::with_limits_and_store(
        session,
        Some(web_token.clone()),
        Some(web_tls),
        web_limits(
            eff.web_max_tunnels,
            eff.web_max_connections,
            eff.web_max_log_lines,
        ),
        Some(web::default_tunnels_path()),
    );
    report_generated_web_credentials(token_was_generated, certificate_was_generated)?;
    let system_tunnels = vec![SystemTunnelSpec {
        role: SystemTunnelRole::WebConsole,
        config: TunnelConfig {
            name: "Web Console".to_string(),
            local_port: eff.web_addr.port(),
            to: to.clone(),
            port: Some(remote_port),
            local_host: "127.0.0.1".to_string(),
            secret: eff.secret.clone(),
        },
        display_url: Some(format!("https://{to}:{remote_port}")),
    }];
    web::run_managed_on_ready(
        web::ServeConfig {
            addr: eff.web_addr,
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
    use std::env;

    use clap::{error::ErrorKind, CommandFactory, Parser};

    use super::{
        parse_local_target, require_to, validate, Eff, Args, Command, DEFAULT_WEB_PORT,
        SSH_DEFAULT_REMOTE_PORT,
    };
    use crate::conf::FileConfig;

    fn empty_eff(args: &Args) -> Eff {
        let _guard = crate::conf::TEST_ENV_GUARD
            .lock()
            .expect("environment lock should not be poisoned");
        Eff::resolve(args, &FileConfig::default())
    }

    fn guarded_env<F: FnOnce()>(f: F) {
        let _guard = crate::conf::TEST_ENV_GUARD
            .lock()
            .expect("environment lock should not be poisoned");
        f();
    }

    #[test]
    fn zero_args_start_local_web_console() {
        let args = Args::try_parse_from(["ltr"]).expect("parse should succeed");
        assert!(args.command.is_none());
        assert!(args.target.is_none());
        assert!(!args.front);
        let eff = empty_eff(&args);
        assert_eq!(eff.web_addr.to_string(), "127.0.0.1:7836");
        assert!(!eff.front);
        assert_eq!(eff.log_level, "info");
    }

    #[test]
    fn parse_bare_port_target() {
        let args = Args::try_parse_from(["ltr", "8000"]).expect("parse should succeed");
        assert_eq!(args.target.as_deref(), Some("8000"));
        assert!(args.command.is_none());
    }

    #[test]
    fn parse_host_port_target_with_tunnel_flags() {
        let args = Args::try_parse_from([
            "ltr",
            "192.168.1.5:8000",
            "-t",
            "example.com",
            "-p",
            "9000",
        ])
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
        assert!(args.is_quick() == false);
    }

    #[test]
    fn quick_commands_never_daemonize() {
        let args = Args::try_parse_from(["ltr", "-l"]).expect("parse should succeed");
        assert!(args.is_quick());
        let args = Args::try_parse_from(["ltr", "-s"]).expect("parse should succeed");
        assert!(args.is_quick());
        let args =
            Args::try_parse_from(["ltr", "conf", "get"]).expect("parse should succeed");
        assert!(args.is_quick());
        let args = Args::try_parse_from(["ltr", "8000"]).expect("parse should succeed");
        assert!(!args.is_quick());
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
        let Some(Command::Web(web_args)) = &args.command else {
            panic!("expected web command");
        };
        assert_eq!(web_args.tunnel.to.as_deref(), Some("example.com"));
        assert_eq!(web_args.tunnel.dport, Some(9000));
    }

    #[test]
    fn ssh_subcommand_parses_with_defaults() {
        let args =
            Args::try_parse_from(["ltr", "ssh", "-t", "example.com"]).expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Ssh(_))));
    }

    #[test]
    fn conf_subcommand_parses() {
        let args = Args::try_parse_from(["ltr", "conf", "get"])
            .expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Conf(_))));
        let args = Args::try_parse_from(["ltr", "conf", "get", "to"])
            .expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Conf(_))));
        let args = Args::try_parse_from(["ltr", "conf", "set", "to", "example.com"])
            .expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Conf(_))));
        let args = Args::try_parse_from(["ltr", "conf", "unset", "to"])
            .expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Conf(_))));
    }

    #[test]
    fn top_level_tunnel_flags_reach_subcommand_modes() {
        let args =
            Args::try_parse_from(["ltr", "-t", "top.example", "web"]).expect("parse should succeed");
        let eff = empty_eff(&args);
        assert_eq!(eff.to.as_deref(), Some("top.example"));

        let args =
            Args::try_parse_from(["ltr", "-t", "top.example", "web", "-t", "sub.example"])
                .expect("parse should succeed");
        let eff = empty_eff(&args);
        assert_eq!(eff.to.as_deref(), Some("sub.example"));
    }

    #[test]
    fn resolution_prefers_cli_over_file_over_env() {
        guarded_env(|| {
            env::remove_var("LTR_SERVER");
            env::remove_var("LTR_LOG_LEVEL");

            let mut file = FileConfig::default();
            // File layer alone.
            file.entries_for_test("to", "file.example");
            let args = Args::try_parse_from(["ltr", "8000"]).expect("parse should succeed");
            let eff = Eff::resolve(&args, &file);
            assert_eq!(eff.to.as_deref(), Some("file.example"));

            // CLI beats file.
            let args = Args::try_parse_from(["ltr", "8000", "-t", "cli.example"])
                .expect("parse should succeed");
            let eff = Eff::resolve(&args, &file);
            assert_eq!(eff.to.as_deref(), Some("cli.example"));

            // Env beats default but loses to file.
            env::set_var("LTR_LOG_LEVEL", "trace");
            let eff = Eff::resolve(&args, &file);
            assert_eq!(eff.log_level, "trace");
            file.entries_for_test("log-level", "debug");
            let eff = Eff::resolve(&args, &file);
            assert_eq!(eff.log_level, "debug");
            env::remove_var("LTR_LOG_LEVEL");
        });
    }

    #[test]
    fn usage_line_shows_command_before_options() {
        let help = Args::command().render_help().to_string();
        assert!(help.contains("Usage: ltr [COMMAND] [OPTIONS]"));
    }

    #[test]
    fn help_shows_only_core_flags() {
        let help = Args::command().render_help().to_string();
        for core in ["-t, --to", "-p, --dport", "-f, --front", "-l, --list", "-s, --stop"] {
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
        assert!(help.contains("ltr conf set to"));
        assert!(!help.contains("npx @qinshower/ltr"));
    }

    #[test]
    fn parse_version_short_flag() {
        let err = Args::try_parse_from(["ltr", "-v"]).expect_err("version should exit");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn parse_hidden_logging_options() {
        let args = Args::try_parse_from(["ltr", "--log-level", "debug", "--log-json", "server"])
            .expect("parse should succeed");
        assert_eq!(args.log_level.as_deref(), Some("debug"));
        assert!(args.log_json);
    }

    #[test]
    fn target_and_subcommand_are_mutually_exclusive() {
        let args = Args::try_parse_from(["ltr", "8000", "server"]).expect("parse should succeed");
        let eff = empty_eff(&args);
        let err = validate(&args, &eff).expect_err("validation should fail");
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn web_requires_loopback_addr() {
        let args = Args::try_parse_from([
            "ltr",
            "--web-addr",
            "0.0.0.0:7836",
            "web",
            "-t",
            "host",
        ])
        .expect("parse should succeed");
        let eff = empty_eff(&args);
        let err = validate(&args, &eff).expect_err("validation should fail");
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn tunnel_tls_conflicts_are_rejected() {
        let args =
            Args::try_parse_from(["ltr", "8000", "-t", "h", "--no-tls", "--tls-ca", "/a"])
                .expect("parse should succeed");
        let eff = empty_eff(&args);
        let err = validate(&args, &eff).expect_err("validation should fail");
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
        let err = require_to(&Eff::resolve(
            &Args::try_parse_from(["ltr", "8000"]).unwrap(),
            &FileConfig::default(),
        ))
        .expect_err("missing to should fail");
        let message = format!("{err:#}");
        assert!(message.contains("ltr conf set to"));
        assert!(message.contains("LTR_SERVER"));

        let mut eff = empty_eff(&Args::try_parse_from(["ltr", "8000"]).unwrap());
        eff.to = Some(" example.com ".to_string());
        assert_eq!(require_to(&eff).unwrap(), "example.com");
    }

    #[test]
    fn web_port_constants() {
        assert_eq!(DEFAULT_WEB_PORT, 7836);
        assert_eq!(SSH_DEFAULT_REMOTE_PORT, 2222);
    }
}
