//! The `ltr conf` configuration subsystem: a typed key registry, the config
//! file (`config.toml` next to `tunnels.toml`), and the three-layer value
//! resolution shared by every command.
//!
//! Priority, highest first: explicit CLI arguments, the config file, `LTR_*`
//! environment variables, built-in defaults.

use std::{
    collections::BTreeMap,
    env, fmt, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

/// Where a resolved value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Saved in the config file.
    File,
    /// Provided through an `LTR_*` environment variable.
    Env,
    /// The built-in default.
    Default,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => f.write_str("file"),
            Self::Env => f.write_str("env"),
            Self::Default => f.write_str("default"),
        }
    }
}

/// The value type of a configuration key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Free-form string.
    Str,
    /// Boolean flag.
    Bool,
    /// 16-bit port number.
    Port,
    /// Unsigned size.
    Usize,
    /// Socket address like 127.0.0.1:7836.
    Addr,
    /// Bare IP address.
    Ip,
    /// Filesystem path.
    Path,
}

impl Kind {
    /// Parses a raw string into the typed shape for this kind.
    fn parse(self, raw: &str) -> Result<String> {
        let raw = raw.trim();
        match self {
            Self::Str => Ok(raw.to_string()),
            Self::Bool => match raw {
                "true" | "yes" | "1" => Ok("true".to_string()),
                "false" | "no" | "0" => Ok("false".to_string()),
                _ => bail!("expected true or false, got {raw:?}"),
            },
            Self::Port => {
                let port: u16 = raw
                    .parse()
                    .with_context(|| format!("expected a port number (0-65535), got {raw:?}"))?;
                Ok(port.to_string())
            }
            Self::Usize => {
                let value: usize = raw
                    .parse()
                    .with_context(|| format!("expected a non-negative integer, got {raw:?}"))?;
                Ok(value.to_string())
            }
            Self::Addr => {
                raw.parse::<SocketAddr>().with_context(|| {
                    format!("expected host:port like 127.0.0.1:7836, got {raw:?}")
                })?;
                Ok(raw.to_string())
            }
            Self::Ip => {
                raw.parse::<IpAddr>()
                    .with_context(|| format!("expected an IP address, got {raw:?}"))?;
                Ok(raw.to_string())
            }
            Self::Path => Ok(raw.to_string()),
        }
    }
}

/// One configuration key: name, type, optional environment variable, and
/// optional built-in default.
#[derive(Debug, Clone)]
pub struct KeySpec {
    /// Long-flag style key name, also the config file key.
    pub name: &'static str,
    /// Value type.
    pub kind: Kind,
    /// Backing environment variable, if any.
    pub env: Option<&'static str>,
    /// Built-in default, if any.
    pub default: Option<&'static str>,
    /// One-line description shown by `conf get`.
    pub help: &'static str,
    /// True when the value is a secret: `conf` output shows it masked, never
    /// in clear text. The builder forces every new key to decide this.
    pub masked: bool,
}

/// Placeholder shown instead of secret values; fixed width so it does not
/// leak the real value's length.
pub const MASKED_VALUE: &str = "********";

impl KeySpec {
    /// Builds an ordinary (non-secret) key specification.
    const fn new(
        name: &'static str,
        kind: Kind,
        env: Option<&'static str>,
        default: Option<&'static str>,
        help: &'static str,
    ) -> Self {
        Self {
            name,
            kind,
            env,
            default,
            help,
            masked: false,
        }
    }

    /// Builds a key whose value is a secret and prints masked.
    const fn secret(
        name: &'static str,
        kind: Kind,
        env: Option<&'static str>,
        default: Option<&'static str>,
        help: &'static str,
    ) -> Self {
        Self {
            masked: true,
            ..Self::new(name, kind, env, default, help)
        }
    }
}

/// Renders a value for terminal display, masking secret keys.
pub fn display_value<'a>(spec: &KeySpec, value: &'a str) -> &'a str {
    if spec.masked {
        MASKED_VALUE
    } else {
        value
    }
}

/// Every configurable key, in display order.
pub static KEYS: &[KeySpec] = &[
    KeySpec::new(
        "to",
        Kind::Str,
        Some("LTR_SERVER"),
        None,
        "Remote relay server for tunnels and web/ssh modes",
    ),
    KeySpec::new(
        "dport",
        Kind::Port,
        None,
        None,
        "Remote port to request; each mode has its own default when unset",
    ),
    KeySpec::secret(
        "secret",
        Kind::Str,
        Some("LTR_SECRET"),
        None,
        "Authentication secret shared with the relay",
    ),
    KeySpec::new(
        "front",
        Kind::Bool,
        Some("LTR_FRONT"),
        Some("false"),
        "Keep commands in the foreground instead of backgrounding",
    ),
    KeySpec::new(
        "ssh-local",
        Kind::Str,
        None,
        Some("22"),
        "Local SSH endpoint forwarded by `ltr ssh` (port or host:port)",
    ),
    KeySpec::new(
        "log-level",
        Kind::Str,
        Some("LTR_LOG_LEVEL"),
        Some("info"),
        "Log filter, for example info or ltr_cli=debug",
    ),
    KeySpec::new(
        "log-json",
        Kind::Bool,
        Some("LTR_LOG_JSON"),
        Some("false"),
        "Emit structured JSON logs",
    ),
    KeySpec::new(
        "web-addr",
        Kind::Addr,
        None,
        Some("127.0.0.1:7836"),
        "Local bind address of the web console",
    ),
    KeySpec::secret(
        "web-token",
        Kind::Str,
        Some("LTR_WEB_TOKEN"),
        None,
        "Bearer token for Web API requests",
    ),
    KeySpec::new(
        "web-cert",
        Kind::Path,
        None,
        None,
        "PEM certificate for remote Web HTTPS",
    ),
    KeySpec::new(
        "web-key",
        Kind::Path,
        None,
        None,
        "PEM private key for remote Web HTTPS",
    ),
    KeySpec::new(
        "web-max-tunnels",
        Kind::Usize,
        Some("LTR_WEB_MAX_TUNNELS"),
        Some("64"),
        "Maximum tunnel definitions in the web console",
    ),
    KeySpec::new(
        "web-max-connections",
        Kind::Usize,
        Some("LTR_WEB_MAX_CONNECTIONS"),
        Some("256"),
        "Maximum active connections per web-managed tunnel",
    ),
    KeySpec::new(
        "web-max-log-lines",
        Kind::Usize,
        Some("LTR_WEB_MAX_LOG_LINES"),
        Some("500"),
        "Maximum retained log lines per web-managed tunnel",
    ),
    KeySpec::new(
        "max-connections",
        Kind::Usize,
        None,
        Some("256"),
        "Maximum concurrent data connections for CLI tunnels",
    ),
    KeySpec::new(
        "no-tls",
        Kind::Bool,
        Some("LTR_NO_TLS"),
        Some("false"),
        "Disable TLS (client tunnels and server)",
    ),
    KeySpec::new(
        "tls-ca",
        Kind::Path,
        Some("LTR_TLS_CA"),
        None,
        "CA PEM validating the remote TLS certificate",
    ),
    KeySpec::new(
        "tls-fingerprint",
        Kind::Str,
        Some("LTR_TLS_FINGERPRINT"),
        None,
        "SHA-256 fingerprint of the remote TLS certificate",
    ),
    KeySpec::new(
        "tls-server-name",
        Kind::Str,
        Some("LTR_TLS_SERVER_NAME"),
        None,
        "TLS server name; defaults to --to",
    ),
    KeySpec::new(
        "tls-client-cert",
        Kind::Path,
        Some("LTR_TLS_CLIENT_CERT"),
        None,
        "Client certificate PEM for mutual tunnel TLS",
    ),
    KeySpec::new(
        "tls-client-key",
        Kind::Path,
        Some("LTR_TLS_CLIENT_KEY"),
        None,
        "Client private key PEM for mutual tunnel TLS",
    ),
    KeySpec::new(
        "min-port",
        Kind::Port,
        Some("LTR_MIN_PORT"),
        Some("1024"),
        "Server: minimum accepted tunnel port",
    ),
    KeySpec::new(
        "max-port",
        Kind::Port,
        Some("LTR_MAX_PORT"),
        Some("65535"),
        "Server: maximum accepted tunnel port",
    ),
    KeySpec::new(
        "bind-addr",
        Kind::Ip,
        None,
        Some("0.0.0.0"),
        "Server: control bind address",
    ),
    KeySpec::new(
        "bind-tunnels",
        Kind::Ip,
        None,
        None,
        "Server: tunnel listener address; defaults to bind-addr",
    ),
    KeySpec::new(
        "tls-cert",
        Kind::Path,
        Some("LTR_TLS_CERT"),
        None,
        "Server: PEM certificate overriding the generated one",
    ),
    KeySpec::new(
        "tls-key",
        Kind::Path,
        Some("LTR_TLS_KEY"),
        None,
        "Server: PEM private key for tunnel TLS",
    ),
    KeySpec::new(
        "tls-client-ca",
        Kind::Path,
        Some("LTR_TLS_CLIENT_CA"),
        None,
        "Server: CA PEM requiring client certificates",
    ),
];

/// Looks up a key specification by name.
pub fn key_spec(name: &str) -> Option<&'static KeySpec> {
    KEYS.iter().find(|spec| spec.name == name)
}

/// The parsed config file.
#[derive(Clone, Default)]
pub struct FileConfig {
    entries: BTreeMap<String, String>,
}

impl fmt::Debug for FileConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self
            .entries
            .iter()
            .map(|(key, value)| {
                let rendered = key_spec(key)
                    .filter(|spec| spec.masked)
                    .map_or(value.as_str(), |_| MASKED_VALUE);
                (key, rendered)
            })
            .collect::<BTreeMap<_, _>>();
        formatter
            .debug_struct("FileConfig")
            .field("entries", &entries)
            .finish()
    }
}

impl FileConfig {
    /// Returns the default config file path.
    pub fn path() -> PathBuf {
        crate::web::registry::config_dir().join("config.toml")
    }

    /// Loads the config file; a missing file is an empty config.
    pub fn load() -> Result<Self> {
        let path = Self::path();
        Self::load_at(&path)
    }

    /// Loads a config file from an explicit path.
    pub fn load_at(path: &Path) -> Result<Self> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("could not read config file {}", path.display()))
            }
        };
        let parsed: BTreeMap<String, toml::Value> =
            toml::from_str(&raw).with_context(|| format!("could not parse {}", path.display()))?;
        let mut entries = BTreeMap::new();
        for (key, value) in parsed {
            let Some(spec) = key_spec(&key) else {
                bail!("unknown config key {key:?}; run `ltr conf get` to list valid keys");
            };
            let value = stringify_toml(&value)
                .with_context(|| format!("config key {key:?} must be a plain value"))?;
            let value = spec
                .kind
                .parse(&value)
                .with_context(|| format!("invalid value for config key {key:?}"))?;
            entries.insert(key, value);
        }
        Ok(Self { entries })
    }

    /// Writes the config file atomically with 0600 permissions.
    pub fn save(&self) -> Result<()> {
        self.save_at(&Self::path())
    }

    /// Writes the config to an explicit path atomically with 0600 permissions.
    pub fn save_at(&self, path: &Path) -> Result<()> {
        let mut raw = String::new();
        for (key, value) in &self.entries {
            let Some(spec) = key_spec(key) else { continue };
            if matches!(spec.kind, Kind::Str | Kind::Path) {
                raw.push_str(&format!("{key} = {value:?}\n"));
            } else {
                raw.push_str(&format!("{key} = {value}\n"));
            }
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("could not create config directory {}", parent.display())
            })?;
        }
        crate::atomic_file::write_atomic(path, raw.as_bytes(), Some(0o600))
            .with_context(|| format!("could not save {}", path.display()))
    }

    /// Returns the raw saved value for a key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Validates and stages a key/value pair; call [`FileConfig::save`] to
    /// persist it.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let spec = key_spec(key).ok_or_else(|| {
            anyhow::anyhow!("unknown config key {key:?}; run `ltr conf get` to list valid keys")
        })?;
        let value = spec
            .kind
            .parse(value)
            .with_context(|| format!("invalid value for {key:?}"))?;
        self.entries.insert(key.to_string(), value);
        Ok(())
    }

    /// Removes a key; missing keys are fine. Call [`FileConfig::save`] to
    /// persist the change.
    pub fn unset(&mut self, key: &str) -> Result<()> {
        key_spec(key).ok_or_else(|| {
            anyhow::anyhow!("unknown config key {key:?}; run `ltr conf get` to list valid keys")
        })?;
        self.entries.remove(key);
        Ok(())
    }

    /// Iterates saved entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.entries.iter()
    }

    /// Inserts a raw entry without validating or saving (tests only).
    #[cfg(test)]
    pub(crate) fn entries_for_test(&mut self, key: &str, value: &str) {
        self.entries.insert(key.to_string(), value.to_string());
    }
}

fn stringify_toml(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// One resolved setting: its value and where it came from.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedValue {
    /// The effective value.
    pub value: String,
    /// The layer that provided it.
    pub source: Source,
}

impl fmt::Debug for ResolvedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedValue")
            .field("value", &MASKED_VALUE)
            .field("source", &self.source)
            .finish()
    }
}

/// Resolves a single key across the three layers below the CLI.
pub fn resolve_below_cli(key: &str, file: &FileConfig) -> Option<ResolvedValue> {
    let spec = key_spec(key)?;
    if let Some(value) = file.get(key) {
        return Some(ResolvedValue {
            value: value.to_string(),
            source: Source::File,
        });
    }
    if let Some(raw) = spec.env.and_then(env::var_os) {
        let raw = raw.to_string_lossy().into_owned();
        let value = spec.kind.parse(&raw).unwrap_or(raw);
        return Some(ResolvedValue {
            value,
            source: Source::Env,
        });
    }
    spec.default.map(|value| ResolvedValue {
        value: value.to_string(),
        source: Source::Default,
    })
}

/// Layers an explicit CLI value over file, environment, and default.
fn layered(key: &str, cli: Option<String>, file: &FileConfig) -> Option<String> {
    cli.or_else(|| resolve_below_cli(key, file).map(|resolved| resolved.value))
}

/// Resolves a string setting across all layers.
pub fn layered_str(key: &str, cli: Option<String>, file: &FileConfig) -> Option<String> {
    layered(key, cli, file)
}

/// Resolves a boolean setting across all layers.
pub fn layered_bool(key: &str, cli: Option<bool>, file: &FileConfig) -> Option<bool> {
    layered(key, cli.map(|v| v.to_string()), file).and_then(|v| v.parse().ok())
}

/// Resolves a SetTrue-style flag across all layers; a false CLI value simply
/// means "not passed" because such flags cannot express an explicit false.
pub fn layered_flag(key: &str, cli: bool, file: &FileConfig) -> Option<bool> {
    if cli {
        return Some(true);
    }
    resolve_below_cli(key, file).map(|resolved| resolved.value == "true")
}

/// Resolves a port setting across all layers.
pub fn layered_u16(key: &str, cli: Option<u16>, file: &FileConfig) -> Option<u16> {
    layered(key, cli.map(|v| v.to_string()), file).and_then(|v| v.parse().ok())
}

/// Resolves a size setting across all layers.
pub fn layered_usize(key: &str, cli: Option<usize>, file: &FileConfig) -> Option<usize> {
    layered(key, cli.map(|v| v.to_string()), file).and_then(|v| v.parse().ok())
}

/// Resolves a socket address setting across all layers.
pub fn layered_addr(key: &str, cli: Option<SocketAddr>, file: &FileConfig) -> Option<SocketAddr> {
    layered(key, cli.map(|v| v.to_string()), file).and_then(|v| v.parse().ok())
}

/// Resolves an IP address setting across all layers.
pub fn layered_ip(key: &str, cli: Option<IpAddr>, file: &FileConfig) -> Option<IpAddr> {
    layered(key, cli.map(|v| v.to_string()), file).and_then(|v| v.parse().ok())
}

/// Resolves a path setting across all layers.
pub fn layered_path(key: &str, cli: Option<PathBuf>, file: &FileConfig) -> Option<PathBuf> {
    layered(key, cli.map(|v| v.to_string_lossy().into_owned()), file).map(PathBuf::from)
}

/// Process-wide guard serializing tests that read or mutate environment
/// variables; shared with the cli test module.
#[cfg(test)]
pub(crate) static TEST_ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use super::{resolve_below_cli, FileConfig, Kind, Source, TEST_ENV_GUARD};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ltr-conf-{tag}-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn set_get_unset_round_trip() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("config.toml");
        let mut conf = FileConfig::load_at(&path).unwrap();
        assert!(conf.get("to").is_none());

        conf.set("to", " example.com ").unwrap();
        conf.save_at(&path).unwrap();
        assert_eq!(conf.get("to"), Some("example.com"));
        let reloaded = FileConfig::load_at(&path).unwrap();
        assert_eq!(reloaded.get("to"), Some("example.com"));

        let mut conf = FileConfig::load_at(&path).unwrap();
        conf.unset("to").unwrap();
        conf.save_at(&path).unwrap();
        assert!(conf.get("to").is_none());
        assert!(FileConfig::load_at(&path).unwrap().get("to").is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn set_validates_values() {
        let dir = temp_dir("validate");
        let path = dir.join("config.toml");
        let mut conf = FileConfig::load_at(&path).unwrap();
        assert!(conf.set("dport", "not-a-port").is_err());
        assert!(conf.set("no-such-key", "x").is_err());
        assert!(conf.set("front", "yes").is_ok());
        assert_eq!(conf.get("front"), Some("true"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saved_file_is_private() {
        let dir = temp_dir("private");
        let path = dir.join("config.toml");
        let mut conf = FileConfig::load_at(&path).unwrap();
        conf.set("secret", "hunter2").unwrap();
        conf.save_at(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_priority_file_over_env_over_default() {
        let _guard = TEST_ENV_GUARD
            .lock()
            .expect("environment lock should not be poisoned");
        let dir = temp_dir("priority");
        let path = dir.join("config.toml");
        let mut conf = FileConfig::load_at(&path).unwrap();
        conf.set("log-level", "debug").unwrap();
        conf.save_at(&path).unwrap();

        std::env::remove_var("LTR_LOG_LEVEL");
        let resolved = resolve_below_cli("log-level", &conf).unwrap();
        assert_eq!(resolved.value, "debug");
        assert_eq!(resolved.source, Source::File);

        // Without a file entry, the env var wins over the default.
        std::env::set_var("LTR_LOG_LEVEL", "warn");
        let conf2 = FileConfig::load_at(&dir.join("missing.toml")).unwrap();
        let resolved = resolve_below_cli("log-level", &conf2).unwrap();
        assert_eq!(resolved.value, "warn");
        assert_eq!(resolved.source, Source::Env);
        std::env::remove_var("LTR_LOG_LEVEL");

        // And the default applies when nothing else is set.
        let resolved = resolve_below_cli("log-level", &conf2).unwrap();
        assert_eq!(resolved.value, "info");
        assert_eq!(resolved.source, Source::Default);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn kinds_parse_and_reject() {
        assert!(Kind::Port.parse("0").is_ok());
        assert!(Kind::Port.parse("70000").is_err());
        assert!(Kind::Addr.parse("127.0.0.1:7836").is_ok());
        assert!(Kind::Addr.parse("127.0.0.1").is_err());
        assert!(Kind::Bool.parse("yes").is_ok());
        assert!(Kind::Bool.parse("maybe").is_err());
    }

    #[test]
    fn resolved_secret_debug_is_redacted() {
        let resolved = super::ResolvedValue {
            value: "relay-secret-value".to_string(),
            source: Source::File,
        };
        assert!(!format!("{resolved:?}").contains("relay-secret-value"));
    }

    #[test]
    fn file_config_debug_redacts_secret_values() {
        let mut config = FileConfig::default();
        config.set("secret", "relay-secret-value").unwrap();
        config.set("web-token", "web-token-value").unwrap();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("relay-secret-value"));
        assert!(!rendered.contains("web-token-value"));
    }

    #[test]
    fn secret_keys_display_masked() {
        let secret = super::key_spec("secret").expect("secret key exists");
        let token = super::key_spec("web-token").expect("web-token key exists");
        assert!(secret.masked);
        assert!(token.masked);
        assert_eq!(super::display_value(secret, "hunter2"), super::MASKED_VALUE);
        assert_eq!(super::display_value(token, "tok-123"), super::MASKED_VALUE);

        let to = super::key_spec("to").expect("to key exists");
        assert!(!to.masked);
        assert_eq!(super::display_value(to, "relay.example"), "relay.example");
    }
}
