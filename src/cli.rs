#![allow(missing_docs)]

use std::{
    env,
    ffi::OsString,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::Result;
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

const WEB_RISK_WARNING: &str =
    "Warning: remote Web access is public. Keep the bearer token private and protect the HTTPS endpoint.";

/// Shared local web console arguments, flattened into every mode that hosts the console.
#[derive(clap::Args, Debug, Clone)]
pub struct WebConsoleArgs {
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
}

/// Top-level CLI arguments.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    disable_version_flag = true,
    after_help = "Examples:\n  ltr\n  ltr local 8000 --to your-server.example\n  ltr bundle --to your-server.example --secret xxx\n  ltr bundle --to your-server.example --no-ssh\n  npx @qinshower/ltr"
)]
pub struct Args {
    /// Prints version information.
    #[arg(short = 'v', long = "version", action = ArgAction::Version)]
    pub version: Option<bool>,

    #[command(flatten)]
    pub web: WebConsoleArgs,

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
    /// Starts a local proxy to the remote server.
    Local(LocalArgs),

    /// Exposes the web console (and SSH by default) through a remote relay.
    Bundle(BundleArgs),

    /// Runs remote proxy server.
    Server(ServerArgs),
}

/// Remote bundle CLI arguments.
#[derive(clap::Args, Debug, Clone)]
pub struct BundleArgs {
    /// Address of remote server to expose home services to.
    #[arg(short, long)]
    pub to: String,

    /// Optional secret for tunnel authentication.
    #[arg(short, long, env = "LTR_SECRET", hide_env_values = true)]
    pub secret: Option<String>,

    #[command(flatten)]
    pub web: WebConsoleArgs,

    /// PEM certificate for remote Web HTTPS.
    #[arg(long = "web-cert", value_name = "PATH")]
    pub web_cert: Option<PathBuf>,

    /// PEM private key for remote Web HTTPS.
    #[arg(long = "web-key", value_name = "PATH")]
    pub web_key: Option<PathBuf>,

    /// Requested remote port for web console tunnel.
    #[arg(long = "web-port", default_value_t = 7836)]
    pub web_port: u16,

    /// Local SSH port to forward.
    #[arg(long = "ssh-local-port", default_value_t = 22)]
    pub ssh_local_port: u16,

    /// Requested remote port for SSH tunnel.
    #[arg(long = "ssh-port", default_value_t = 2222)]
    pub ssh_port: u16,

    /// Skip the SSH tunnel and only expose the web console.
    #[arg(long = "no-ssh", action = ArgAction::SetTrue)]
    pub no_ssh: bool,
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

    /// Disable tunnel TLS. TLS is enabled by default with a generated certificate.
    #[arg(long = "no-tls", env = "LTR_NO_TLS", action = ArgAction::SetTrue)]
    pub no_tls: bool,

    /// PEM certificate overriding the default generated tunnel certificate.
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
        Some(Command::Bundle(bundle_args)) if !bundle_args.web.web_addr.ip().is_loopback() => {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "bundle mode requires --web-addr to bind to loopback",
            ))
        }
        Some(Command::Local(local_args))
            if local_args.no_tls
                && (local_args.tls_ca.is_some()
                    || local_args.tls_fingerprint.is_some()
                    || local_args.tls_server_name.is_some()
                    || local_args.tls_client_cert.is_some()
                    || local_args.tls_client_key.is_some()) =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls-ca, --tls-fingerprint, --tls-server-name, --tls-client-cert, and --tls-client-key cannot be used with --no-tls",
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
            if server_args.tls_client_ca.is_some() && server_args.no_tls =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls-client-ca cannot be used with --no-tls",
            ))
        }
        Some(Command::Server(server_args))
            if server_args.no_tls && (server_args.tls_cert.is_some() || server_args.tls_key.is_some()) =>
        {
            Err(Args::command().error(
                ErrorKind::InvalidValue,
                "--tls-cert and --tls-key cannot be used with --no-tls",
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
        None => {
            return run_web_local(
                args.web.web_addr,
                args.web.web_token,
                web_limits(
                    args.web.web_max_tunnels,
                    args.web.web_max_connections,
                    args.web.web_max_log_lines,
                ),
            )
            .await;
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
    let state = WebState::with_limits_and_store(
        SessionInfo::local(),
        web_token,
        None,
        limits,
        Some(web::default_tunnels_path()),
    );
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

pub async fn run_bundle(args: BundleArgs) -> Result<()> {
    let include_ssh = !args.no_ssh;
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
    let session = SessionInfo {
        mode: if include_ssh {
            SessionMode::Home
        } else {
            SessionMode::RemoteWeb
        },
        warnings: vec![WEB_RISK_WARNING.to_string()],
        loopback_only: true,
        web_remote_url: Some(format!("https://{}:{}", args.to, args.web_port)),
        ssh_remote_endpoint: include_ssh.then(|| format!("{}:{}", args.to, args.ssh_port)),
    };
    let token_was_generated = args.web.web_token.is_none();
    let certificate_was_generated = args.web_cert.is_none();
    let web_token = credentials::load_or_generate(args.web.web_token)?;
    let web_tls = credentials::load_or_generate_tls(
        &args.to,
        args.web_cert.as_deref(),
        args.web_key.as_deref(),
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
    if include_ssh {
        println!("SSH access: ssh {user}@{} -p {}", args.to, args.ssh_port);
    }
    let mut system_tunnels = vec![SystemTunnelSpec {
        role: SystemTunnelRole::WebConsole,
        config: TunnelConfig {
            name: "Web Console".to_string(),
            local_port: args.web.web_addr.port(),
            to: args.to.clone(),
            port: Some(args.web_port),
            local_host: "127.0.0.1".to_string(),
            secret: args.secret.clone(),
        },
        display_url: Some(format!("https://{}:{}", args.to, args.web_port)),
    }];
    if include_ssh {
        system_tunnels.push(SystemTunnelSpec {
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
        });
    }
    web::run_managed(
        web::ServeConfig {
            addr: args.web.web_addr,
            session: state.session().await,
        },
        state,
        system_tunnels,
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
    fn zero_args_start_local_web_console() {
        let args = Args::try_parse_from(["ltr"]).expect("parse should succeed");
        assert!(args.command.is_none());
        assert_eq!(args.web.web_addr.to_string(), "127.0.0.1:7836");
    }

    #[test]
    fn web_flag_is_removed() {
        let err = Args::try_parse_from(["ltr", "--web"]).expect_err("--web is removed");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
        let err = Args::try_parse_from(["ltr", "-w"]).expect_err("-w is removed");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn parse_web_addr() {
        let args = Args::try_parse_from(["ltr", "--web-addr", "127.0.0.1:9000"])
            .expect("parse should succeed");
        assert_eq!(args.web.web_addr.to_string(), "127.0.0.1:9000");
        assert!(args.command.is_none());
    }

    #[test]
    fn parse_existing_local_command() {
        let args = Args::try_parse_from(["ltr", "local", "8000", "--to", "bore.pub"])
            .expect("parse should succeed");
        assert!(args.command.is_some());
    }

    #[test]
    fn web_subcommand_is_removed() {
        let err = Args::try_parse_from(["ltr", "web"]).expect_err("web subcommand is removed");
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn parse_bundle_no_ssh() {
        let args = Args::try_parse_from(["ltr", "bundle", "--to", "host", "--no-ssh"])
            .expect("parse should succeed");
        let Some(Command::Bundle(bundle)) = args.command else {
            panic!("expected bundle command");
        };
        assert_eq!(bundle.to, "host");
        assert!(bundle.no_ssh);
    }

    #[test]
    fn bundle_defaults_to_ssh_enabled() {
        let args =
            Args::try_parse_from(["ltr", "bundle", "--to", "host"]).expect("parse should succeed");
        let Some(Command::Bundle(bundle)) = args.command else {
            panic!("expected bundle command");
        };
        assert!(!bundle.no_ssh);
        assert_eq!(bundle.ssh_port, 2222);
    }

    #[test]
    fn parse_logging_options() {
        let args = Args::try_parse_from(["ltr", "--log-level", "debug", "--log-json", "server"])
            .expect("parse should succeed");
        assert_eq!(args.log_level, "debug");
        assert!(args.log_json);
    }

    #[test]
    fn parse_bundle_subcommand() {
        let args =
            Args::try_parse_from(["ltr", "bundle", "--to", "host"]).expect("parse should succeed");
        assert!(matches!(args.command, Some(Command::Bundle(_))));
    }

    #[test]
    fn home_alias_is_removed() {
        let err = Args::try_parse_from(["ltr", "home", "--to", "host"])
            .expect_err("home alias should be removed");
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
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
    fn bore_env_variables_are_not_promoted() {
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
        assert_eq!(server.secret.as_deref(), None);

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
    fn validate_bundle_requires_loopback_addr() {
        let args = Args::try_parse_from([
            "ltr",
            "bundle",
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
        let args = Args::try_parse_from(["ltr", "server", "--bind-addr", "0.0.0.0"])
            .expect("parse should succeed");
        assert!(args.command.is_some());
    }

    #[test]
    fn parse_version_short_flag() {
        let err = Args::try_parse_from(["bore", "-v"]).expect_err("version should exit");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn help_mentions_zero_arg_and_bundle_usage() {
        let help = Args::command().render_long_help().to_string();
        assert!(help.contains("ltr bundle --to your-server.example --secret xxx"));
        assert!(help.contains("ltr bundle --to your-server.example --no-ssh"));
        assert!(help.contains("npx @qinshower/ltr"));
    }
}
