#![allow(missing_docs)]

use std::{
    env,
    ffi::OsString,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use clap::{error::ErrorKind, ArgAction, CommandFactory, Parser, Subcommand};

use crate::{
    client::{run_local, LocalArgs},
    server::Server,
    transport,
    web::{
        self, credentials, SessionInfo, SessionMode, SystemTunnelRole, SystemTunnelSpec,
        TunnelConfig, WebLimits, WebState,
    },
};

const LEGACY_ENV_ALIASES: &[(&str, &str)] = &[
    ("LTR_LOCAL_PORT", "BORE_LOCAL_PORT"),
    ("LTR_SERVER", "BORE_SERVER"),
    ("LTR_SECRET", "BORE_SECRET"),
    ("LTR_WEB_TOKEN", "BORE_WEB_TOKEN"),
    ("LTR_MIN_PORT", "BORE_MIN_PORT"),
    ("LTR_MAX_PORT", "BORE_MAX_PORT"),
];

const WEB_RISK_WARNING: &str =
    "Warning: remote Web access is public. Keep the bearer token private and protect the HTTPS endpoint.";

/// Top-level CLI arguments.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    disable_version_flag = true,
    after_help = "Examples:\n  ltr local 8000 --to your-server.example\n  ltr -w\n  ltr web --remote --to your-server.example --port 7836 --secret xxx\n  ltr bundle --to your-server.example --secret xxx\n  npx @qinshower/ltr web\n  npx @qinshower/ltr -- -w"
)]
pub struct Args {
    /// Prints version information.
    #[arg(short = 'v', long = "version", action = ArgAction::Version)]
    pub version: Option<bool>,

    /// Starts the local web console.
    #[arg(short = 'w', long = "web")]
    pub web: bool,

    /// Address for the local web console.
    #[arg(long = "web-addr", default_value = "127.0.0.1:7836")]
    pub web_addr: SocketAddr,

    /// Bearer token for Web API requests.
    #[arg(long = "web-token", env = "LTR_WEB_TOKEN", hide_env_values = true)]
    pub web_token: Option<String>,

    /// Maximum number of tunnel definitions in the Web control plane.
    #[arg(
        long = "web-max-tunnels",
        env = "LTR_WEB_MAX_TUNNELS",
        default_value_t = 64
    )]
    pub web_max_tunnels: usize,

    /// Maximum active data connections per Web-managed tunnel.
    #[arg(
        long = "web-max-connections",
        env = "LTR_WEB_MAX_CONNECTIONS",
        default_value_t = 256
    )]
    pub web_max_connections: usize,

    /// Maximum retained log lines per Web-managed tunnel.
    #[arg(
        long = "web-max-log-lines",
        env = "LTR_WEB_MAX_LOG_LINES",
        default_value_t = 500
    )]
    pub web_max_log_lines: usize,

    /// Log filter, for example info or ltr_cli=debug.
    #[arg(long = "log-level", env = "LTR_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Emit structured JSON logs instead of human-readable logs.
    #[arg(long = "log-json", env = "LTR_LOG_JSON", default_value_t = false)]
    pub log_json: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Parses CLI arguments after promoting legacy environment variable names.
pub fn parse_args() -> Args {
    parse_args_from(env::args_os())
}

/// Initialize logging from parsed CLI and environment settings.
pub fn init_logging(args: &Args) {
    let filter = tracing_subscriber::EnvFilter::try_new(&args.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if args.log_json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// Parses an argument iterator with the same environment compatibility rules as the binary.
pub fn parse_args_from<I, T>(args: I) -> Args
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    promote_legacy_env();
    Args::parse_from(args)
}

fn promote_legacy_env() {
    for (canonical, legacy) in LEGACY_ENV_ALIASES {
        let Some(value) = env::var_os(legacy) else {
            continue;
        };

        if env::var_os(canonical).is_none() {
            env::set_var(canonical, value);
            eprintln!("Warning: {legacy} is deprecated; use {canonical} instead.");
        } else {
            eprintln!("Warning: {legacy} is deprecated and ignored; use {canonical} instead.");
        }
    }
}

/// Top-level command variants.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Starts a local proxy to the remote server.
    Local(LocalArgs),

    /// Starts web console. Prefer this form for `npx`.
    Web(WebArgs),

    /// Starts Web + SSH bundle with remote system tunnels.
    #[command(alias = "home")]
    Bundle(BundleArgs),

    /// Runs remote proxy server.
    Server(ServerArgs),
}

/// Web console CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct WebArgs {
    /// Address for local web console.
    #[arg(long = "web-addr", default_value = "127.0.0.1:7836")]
    pub web_addr: SocketAddr,

    /// Expose web console through remote tunnel on target server.
    #[arg(long, requires = "to")]
    pub remote: bool,

    /// Address of remote server to expose web console to.
    #[arg(short, long)]
    pub to: Option<String>,

    /// Requested remote port for web console tunnel.
    #[arg(short, long, default_value_t = 7836)]
    pub port: u16,

    /// Optional secret for tunnel authentication.
    #[arg(short, long, env = "LTR_SECRET", hide_env_values = true)]
    pub secret: Option<String>,

    /// Bearer token for remote Web API requests.
    #[arg(long = "web-token", env = "LTR_WEB_TOKEN", hide_env_values = true)]
    pub web_token: Option<String>,

    /// PEM certificate for remote Web HTTPS.
    #[arg(long = "web-cert", value_name = "PATH")]
    pub web_cert: Option<PathBuf>,

    /// PEM private key for remote Web HTTPS.
    #[arg(long = "web-key", value_name = "PATH")]
    pub web_key: Option<PathBuf>,

    /// Maximum number of tunnel definitions in the Web control plane.
    #[arg(
        long = "web-max-tunnels",
        env = "LTR_WEB_MAX_TUNNELS",
        default_value_t = 64
    )]
    pub web_max_tunnels: usize,

    /// Maximum active data connections per Web-managed tunnel.
    #[arg(
        long = "web-max-connections",
        env = "LTR_WEB_MAX_CONNECTIONS",
        default_value_t = 256
    )]
    pub web_max_connections: usize,

    /// Maximum retained log lines per Web-managed tunnel.
    #[arg(
        long = "web-max-log-lines",
        env = "LTR_WEB_MAX_LOG_LINES",
        default_value_t = 500
    )]
    pub web_max_log_lines: usize,
}

/// Home bundle CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct BundleArgs {
    /// Address of remote server to expose home services to.
    #[arg(short, long)]
    pub to: String,

    /// Optional secret for tunnel authentication.
    #[arg(short, long, env = "LTR_SECRET", hide_env_values = true)]
    pub secret: Option<String>,

    /// Bearer token for remote Web API requests.
    #[arg(long = "web-token", env = "LTR_WEB_TOKEN", hide_env_values = true)]
    pub web_token: Option<String>,

    /// PEM certificate for remote Web HTTPS.
    #[arg(long = "web-cert", value_name = "PATH")]
    pub web_cert: Option<PathBuf>,

    /// PEM private key for remote Web HTTPS.
    #[arg(long = "web-key", value_name = "PATH")]
    pub web_key: Option<PathBuf>,

    /// Maximum number of tunnel definitions in the Web control plane.
    #[arg(
        long = "web-max-tunnels",
        env = "LTR_WEB_MAX_TUNNELS",
        default_value_t = 64
    )]
    pub web_max_tunnels: usize,

    /// Maximum active data connections per Web-managed tunnel.
    #[arg(
        long = "web-max-connections",
        env = "LTR_WEB_MAX_CONNECTIONS",
        default_value_t = 256
    )]
    pub web_max_connections: usize,

    /// Maximum retained log lines per Web-managed tunnel.
    #[arg(
        long = "web-max-log-lines",
        env = "LTR_WEB_MAX_LOG_LINES",
        default_value_t = 500
    )]
    pub web_max_log_lines: usize,

    /// Address for local web console.
    #[arg(long = "web-addr", default_value = "127.0.0.1:7836")]
    pub web_addr: SocketAddr,

    /// Requested remote port for web console tunnel.
    #[arg(long = "web-port", default_value_t = 7836)]
    pub web_port: u16,

    /// Local SSH port to forward.
    #[arg(long = "ssh-local-port", default_value_t = 22)]
    pub ssh_local_port: u16,

    /// Requested remote port for SSH tunnel.
    #[arg(long = "ssh-port", default_value_t = 2222)]
    pub ssh_port: u16,
}

/// Server CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct ServerArgs {
    /// Minimum accepted TCP port number.
    #[arg(long, default_value_t = 1024, env = "LTR_MIN_PORT")]
    pub min_port: u16,

    /// Maximum accepted TCP port number.
    #[arg(long, default_value_t = 65535, env = "LTR_MAX_PORT")]
    pub max_port: u16,

    /// Optional secret for authentication.
    #[arg(short, long, env = "LTR_SECRET", hide_env_values = true)]
    pub secret: Option<String>,

    /// IP address to bind to, clients must reach this.
    #[arg(long, default_value = "0.0.0.0")]
    pub bind_addr: IpAddr,

    /// IP address where tunnels will listen on, defaults to --bind-addr.
    #[arg(long)]
    pub bind_tunnels: Option<IpAddr>,

    /// Enable tunnel TLS, generating and persisting a certificate when paths are omitted.
    #[arg(long, env = "LTR_TLS")]
    pub tls: bool,

    /// PEM certificate used by optional tunnel TLS.
    #[arg(long = "tls-cert", env = "LTR_TLS_CERT", value_name = "PATH")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key used by optional tunnel TLS.
    #[arg(long = "tls-key", env = "LTR_TLS_KEY", value_name = "PATH")]
    pub tls_key: Option<PathBuf>,

    /// CA PEM used to require client certificates during tunnel TLS.
    #[arg(long = "tls-client-ca", env = "LTR_TLS_CLIENT_CA", value_name = "PATH")]
    pub tls_client_ca: Option<PathBuf>,
}

/// Validates parsed CLI arguments.
pub fn validate_args(args: &Args) -> std::result::Result<(), clap::Error> {
    match &args.command {
        Some(Command::Web(web_args))
            if web_args.remote && !web_args.web_addr.ip().is_loopback() =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "remote web mode requires --web-addr to bind to loopback",
            ))
        }
        Some(Command::Bundle(bundle_args)) if !bundle_args.web_addr.ip().is_loopback() => {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "bundle mode requires --web-addr to bind to loopback",
            ))
        }
        Some(Command::Local(local_args))
            if !local_args.tls
                && (local_args.tls_ca.is_some()
                    || local_args.tls_fingerprint.is_some()
                    || local_args.tls_server_name.is_some()
                    || local_args.tls_client_cert.is_some()
                    || local_args.tls_client_key.is_some()) =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls-ca, --tls-fingerprint, and --tls-server-name require --tls",
            ))
        }
        Some(Command::Local(local_args))
            if local_args.tls
                && local_args.tls_ca.is_none()
                && local_args.tls_fingerprint.is_none() =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls requires --tls-ca or --tls-fingerprint",
            ))
        }
        Some(Command::Local(local_args))
            if local_args.tls_client_cert.is_some() != local_args.tls_client_key.is_some() =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls-client-cert and --tls-client-key must be provided together",
            ))
        }
        Some(Command::Web(web_args))
            if web_args.web_cert.is_some() != web_args.web_key.is_some() =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--web-cert and --web-key must be provided together",
            ))
        }
        Some(Command::Web(web_args))
            if !web_args.remote && (web_args.web_cert.is_some() || web_args.web_key.is_some()) =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--web-cert and --web-key require --remote",
            ))
        }
        Some(Command::Bundle(bundle_args))
            if bundle_args.web_cert.is_some() != bundle_args.web_key.is_some() =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--web-cert and --web-key must be provided together",
            ))
        }
        Some(Command::Server(server_args))
            if server_args.tls_cert.is_some() != server_args.tls_key.is_some() =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls-cert and --tls-key must be provided together",
            ))
        }
        Some(Command::Server(server_args))
            if server_args.tls_client_ca.is_some()
                && !server_args.tls
                && server_args.tls_cert.is_none()
                && server_args.tls_key.is_none() =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls-client-ca requires --tls or --tls-cert and --tls-key",
            ))
        }
        _ => Ok(()),
    }
}

/// Runs parsed CLI command.
pub async fn run(args: Args) -> Result<()> {
    if let Err(err) = validate_args(&args) {
        err.exit();
    }

    match args.command {
        Some(_) if args.web => {
            Args::command()
                .error(
                    ErrorKind::ArgumentConflict,
                    "--web cannot be used together with a subcommand",
                )
                .exit();
        }
        None if args.web => {
            return run_web_local(
                args.web_addr,
                args.web_token,
                web_limits(
                    args.web_max_tunnels,
                    args.web_max_connections,
                    args.web_max_log_lines,
                ),
            )
            .await;
        }
        None => {
            Args::command()
                .error(
                    ErrorKind::MissingSubcommand,
                    "a subcommand is required unless --web is used",
                )
                .exit();
        }
        Some(Command::Local(local_args)) => {
            run_local(
                local_args,
                async {
                    let _ = tokio::signal::ctrl_c().await;
                },
                None,
            )
            .await?;
        }
        Some(Command::Web(web_args)) => {
            if web_args.remote {
                run_web_remote(web_args).await?;
            } else {
                run_web_local(
                    web_args.web_addr,
                    web_args.web_token,
                    web_limits(
                        web_args.web_max_tunnels,
                        web_args.web_max_connections,
                        web_args.web_max_log_lines,
                    ),
                )
                .await?;
            }
        }
        Some(Command::Bundle(bundle_args)) => {
            run_bundle(bundle_args).await?;
        }
        Some(Command::Server(server_args)) => {
            let port_range = server_args.min_port..=server_args.max_port;
            if port_range.is_empty() {
                Args::command()
                    .error(ErrorKind::InvalidValue, "port range is empty")
                    .exit();
            }
            let mut server = Server::new(port_range, server_args.secret.as_deref());
            server.set_bind_addr(server_args.bind_addr);
            server.set_bind_tunnels(server_args.bind_tunnels.unwrap_or(server_args.bind_addr));
            let tls_requested = server_args.tls
                || server_args.tls_cert.is_some()
                || server_args.tls_key.is_some()
                || server_args.tls_client_ca.is_some();
            if tls_requested {
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
    }

    Ok(())
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
) -> Result<()> {
    if !web_addr.ip().is_loopback() && web_token.is_none() {
        eprintln!(
            "Warning: Web console is exposed on a non-loopback address without Web authentication."
        );
    }
    let state = WebState::with_limits(SessionInfo::local(), web_token, None, limits);
    web::serve_with_state(
        web::ServeConfig {
            addr: web_addr,
            session: state.session().await,
        },
        state,
        tokio::signal::ctrl_c(),
    )
    .await
}

pub async fn run_web_remote(args: WebArgs) -> Result<()> {
    let server = args
        .to
        .clone()
        .ok_or_else(|| anyhow!("--to is required when --remote is used"))?;
    let session = SessionInfo {
        mode: SessionMode::RemoteWeb,
        warnings: vec![WEB_RISK_WARNING.to_string()],
        loopback_only: true,
        web_remote_url: Some(format!("https://{}:{}", server, args.port)),
        ssh_remote_endpoint: None,
    };
    let token_was_generated = args.web_token.is_none();
    let certificate_was_generated = args.web_cert.is_none();
    let web_token = credentials::load_or_generate(args.web_token)?;
    let web_tls = credentials::load_or_generate_tls(
        &server,
        args.web_cert.as_deref(),
        args.web_key.as_deref(),
    )?;
    let state = WebState::with_limits(
        session,
        Some(web_token.clone()),
        Some(web_tls),
        web_limits(
            args.web_max_tunnels,
            args.web_max_connections,
            args.web_max_log_lines,
        ),
    );
    report_generated_web_credentials(token_was_generated, certificate_was_generated)?;
    let display_url = format!("https://{}:{}", server, args.port);
    web::run_managed(
        web::ServeConfig {
            addr: args.web_addr,
            session: state.session().await,
        },
        state,
        vec![SystemTunnelSpec {
            role: SystemTunnelRole::WebConsole,
            config: TunnelConfig {
                name: "Web Console".to_string(),
                local_port: args.web_addr.port(),
                to: server,
                port: Some(args.port),
                local_host: "127.0.0.1".to_string(),
                secret: args.secret,
            },
            display_url: Some(display_url),
        }],
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
    )
    .await
}

pub async fn run_bundle(args: BundleArgs) -> Result<()> {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
    let session = SessionInfo {
        mode: SessionMode::Home,
        warnings: vec![WEB_RISK_WARNING.to_string()],
        loopback_only: true,
        web_remote_url: Some(format!("https://{}:{}", args.to, args.web_port)),
        ssh_remote_endpoint: Some(format!("{}:{}", args.to, args.ssh_port)),
    };
    let token_was_generated = args.web_token.is_none();
    let certificate_was_generated = args.web_cert.is_none();
    let web_token = credentials::load_or_generate(args.web_token)?;
    let web_tls = credentials::load_or_generate_tls(
        &args.to,
        args.web_cert.as_deref(),
        args.web_key.as_deref(),
    )?;
    let state = WebState::with_limits(
        session,
        Some(web_token.clone()),
        Some(web_tls),
        web_limits(
            args.web_max_tunnels,
            args.web_max_connections,
            args.web_max_log_lines,
        ),
    );
    report_generated_web_credentials(token_was_generated, certificate_was_generated)?;
    println!("SSH access: ssh {user}@{} -p {}", args.to, args.ssh_port);
    web::run_managed(
        web::ServeConfig {
            addr: args.web_addr,
            session: state.session().await,
        },
        state,
        vec![
            SystemTunnelSpec {
                role: SystemTunnelRole::WebConsole,
                config: TunnelConfig {
                    name: "Web Console".to_string(),
                    local_port: args.web_addr.port(),
                    to: args.to.clone(),
                    port: Some(args.web_port),
                    local_host: "127.0.0.1".to_string(),
                    secret: args.secret.clone(),
                },
                display_url: Some(format!("https://{}:{}", args.to, args.web_port)),
            },
            SystemTunnelSpec {
                role: SystemTunnelRole::Ssh,
                config: TunnelConfig {
                    name: "SSH".to_string(),
                    local_port: args.ssh_local_port,
                    to: args.to.clone(),
                    port: Some(args.ssh_port),
                    local_host: "127.0.0.1".to_string(),
                    secret: args.secret,
                },
                display_url: Some(format!("{}:{}", args.to, args.ssh_port)),
            },
        ],
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{env, sync::Mutex};

    use clap::{error::ErrorKind, CommandFactory, Parser};

    use super::{validate_args, Args, Command};

    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_web_long_flag() {
        let args = Args::try_parse_from(["bore", "--web"]).expect("parse should succeed");
        assert!(args.web);
        assert_eq!(args.web_addr.to_string(), "127.0.0.1:7836");
        assert!(args.command.is_none());
    }

    #[test]
    fn parse_web_short_flag() {
        let args = Args::try_parse_from(["bore", "-w"]).expect("parse should succeed");
        assert!(args.web);
    }

    #[test]
    fn parse_web_addr() {
        let args = Args::try_parse_from(["bore", "--web", "--web-addr", "127.0.0.1:9000"])
            .expect("parse should succeed");
        assert_eq!(args.web_addr.to_string(), "127.0.0.1:9000");
    }

    #[test]
    fn parse_existing_local_command() {
        let args = Args::try_parse_from(["bore", "local", "8000", "--to", "bore.pub"])
            .expect("parse should succeed");
        assert!(!args.web);
        assert!(args.command.is_some());
    }

    #[test]
    fn parse_web_subcommand() {
        let args = Args::try_parse_from(["bore", "web", "--web-addr", "127.0.0.1:9000"])
            .expect("parse should succeed");
        assert!(!args.web);
        assert!(matches!(args.command, Some(Command::Web(_))));
    }

    #[test]
    fn parse_remote_web_subcommand() {
        let args = Args::try_parse_from(["bore", "web", "--remote", "--to", "host"])
            .expect("parse should succeed");
        let Some(Command::Web(web)) = args.command else {
            panic!("expected web command");
        };
        assert!(web.remote);
        assert_eq!(web.to.as_deref(), Some("host"));
    }

    #[test]
    fn parse_web_token() {
        let args = Args::try_parse_from(["ltr", "web", "--web-token", "token"])
            .expect("parse should succeed");
        let Some(Command::Web(web)) = args.command else {
            panic!("expected web command");
        };
        assert_eq!(web.web_token.as_deref(), Some("token"));
    }

    #[test]
    fn parse_logging_options() {
        let args = Args::try_parse_from(["ltr", "--log-level", "debug", "--log-json", "server"])
            .expect("parse should succeed");
        assert_eq!(args.log_level, "debug");
        assert!(args.log_json);
    }

    #[test]
    fn parse_home_subcommand() {
        let args =
            Args::try_parse_from(["bore", "home", "--to", "host"]).expect("parse should succeed");
        let Some(Command::Bundle(bundle)) = args.command else {
            panic!("expected bundle command");
        };
        assert_eq!(bundle.to, "host");
        assert_eq!(bundle.web_port, 7836);
        assert_eq!(bundle.ssh_port, 2222);
    }

    #[test]
    fn parse_bundle_subcommand() {
        let args =
            Args::try_parse_from(["ltr", "bundle", "--to", "host"]).expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Bundle(_))));
    }

    #[test]
    fn bundle_is_visible_and_home_remains_alias() {
        let command = Args::command();
        assert!(command
            .get_subcommands()
            .any(|subcommand| subcommand.get_name() == "bundle"));
        let args =
            Args::try_parse_from(["bore", "home", "--to", "host"]).expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Bundle(_))));
    }

    #[test]
    fn parse_server_tls_generation_flag() {
        let args = Args::try_parse_from(["ltr", "server", "--tls"]).expect("parse should succeed");
        let Some(Command::Server(server)) = args.command else {
            panic!("expected server command");
        };
        assert!(server.tls);
    }

    #[test]
    fn legacy_bore_secret_env_maps_to_ltr() {
        let _guard = ENV_GUARD
            .lock()
            .expect("environment lock should not be poisoned");
        let old_ltr = env::var_os("LTR_SECRET");
        let old_bore = env::var_os("BORE_SECRET");
        env::remove_var("LTR_SECRET");
        env::set_var("BORE_SECRET", "legacy-secret");

        let args = super::parse_args_from(["ltr", "server"]);
        let Some(Command::Server(server)) = args.command else {
            panic!("expected server command");
        };
        assert_eq!(server.secret.as_deref(), Some("legacy-secret"));

        match old_ltr {
            Some(value) => env::set_var("LTR_SECRET", value),
            None => env::remove_var("LTR_SECRET"),
        }
        match old_bore {
            Some(value) => env::set_var("BORE_SECRET", value),
            None => env::remove_var("BORE_SECRET"),
        }
    }

    #[test]
    fn parse_web_remote_missing_to_fails() {
        let err = Args::try_parse_from(["bore", "web", "--remote"]).expect_err("parse should fail");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn validate_remote_web_requires_loopback_addr() {
        let args = Args::try_parse_from([
            "bore",
            "web",
            "--remote",
            "--to",
            "host",
            "--web-addr",
            "0.0.0.0:7836",
        ])
        .expect("parse should succeed");
        let err = validate_args(&args).expect_err("validation should fail");
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn parse_existing_server_command() {
        let args = Args::try_parse_from(["bore", "server", "--bind-addr", "0.0.0.0"])
            .expect("parse should succeed");
        assert!(!args.web);
        assert!(args.command.is_some());
    }

    #[test]
    fn parse_version_short_flag() {
        let err = Args::try_parse_from(["bore", "-v"]).expect_err("version should exit");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn help_mentions_web_remote_and_bundle_usage() {
        let help = Args::command().render_long_help().to_string();
        assert!(help.contains("-w, --web"));
        assert!(help.contains("ltr web --remote --to your-server.example --port 7836 --secret xxx"));
        assert!(help.contains("ltr bundle --to your-server.example --secret xxx"));
        assert!(help.contains("npx @qinshower/ltr -- -w"));
    }
}
