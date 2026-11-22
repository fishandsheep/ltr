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
}

/// Every configurable key, in display order.
pub static KEYS: &[KeySpec] = &[
    KeySpec {
        name: "to",
        kind: Kind::Str,
        env: Some("LTR_SERVER"),
        default: None,
        help: "Remote relay server for tunnels and web/ssh modes",
    },
    KeySpec {
        name: "dport",
        kind: Kind::Port,
        env: None,
        default: None,
        help: "Remote port to request; each mode has its own default when unset",
    },
    KeySpec {
        name: "secret",
        kind: Kind::Str,
        env: Some("LTR_SECRET"),
        default: None,
        help: "Authentication secret shared with the relay",
    },
    KeySpec {
        name: "front",
        kind: Kind::Bool,
        env: Some("LTR_FRONT"),
        default: Some("false"),
        help: "Keep commands in the foreground instead of backgrounding",
    },
    KeySpec {
        name: "ssh-local",
        kind: Kind::Str,
        env: None,
        default: Some("22"),
        help: "Local SSH endpoint forwarded by `ltr ssh` (port or host:port)",
    },
    KeySpec {
        name: "log-level",
        kind: Kind::Str,
        env: Some("LTR_LOG_LEVEL"),
        default: Some("info"),
        help: "Log filter, for example info or ltr_cli=debug",
    },
    KeySpec {
        name: "log-json",
        kind: Kind::Bool,
        env: Some("LTR_LOG_JSON"),
        default: Some("false"),
        help: "Emit structured JSON logs",
    },
    KeySpec {
        name: "web-addr",
        kind: Kind::Addr,
        env: None,
        default: Some("127.0.0.1:7836"),
        help: "Local bind address of the web console",
    },
    KeySpec {
        name: "web-token",
        kind: Kind::Str,
        env: Some("LTR_WEB_TOKEN"),
        default: None,
        help: "Bearer token for Web API requests",
    },
    KeySpec {
        name: "web-cert",
        kind: Kind::Path,
        env: None,
        default: None,
        help: "PEM certificate for remote Web HTTPS",
    },
    KeySpec {
        name: "web-key",
        kind: Kind::Path,
        env: None,
        default: None,
        help: "PEM private key for remote Web HTTPS",
    },
    KeySpec {
        name: "web-max-tunnels",
        kind: Kind::Usize,
        env: Some("LTR_WEB_MAX_TUNNELS"),
        default: Some("64"),
        help: "Maximum tunnel definitions in the web console",
    },
    KeySpec {
        name: "web-max-connections",
        kind: Kind::Usize,
        env: Some("LTR_WEB_MAX_CONNECTIONS"),
        default: Some("256"),
        help: "Maximum active connections per web-managed tunnel",
    },
    KeySpec {
        name: "web-max-log-lines",
        kind: Kind::Usize,
        env: Some("LTR_WEB_MAX_LOG_LINES"),
        default: Some("500"),
        help: "Maximum retained log lines per web-managed tunnel",
    },
    KeySpec {
        name: "max-connections",
        kind: Kind::Usize,
        env: None,
        default: Some("256"),
        help: "Maximum concurrent data connections for CLI tunnels",
    },
    KeySpec {
        name: "no-tls",
        kind: Kind::Bool,
        env: Some("LTR_NO_TLS"),
        default: Some("false"),
        help: "Disable TLS (client tunnels and server)",
    },
    KeySpec {
        name: "tls-ca",
        kind: Kind::Path,
        env: Some("LTR_TLS_CA"),
        default: None,
        help: "CA PEM validating the remote TLS certificate",
    },
    KeySpec {
        name: "tls-fingerprint",
        kind: Kind::Str,
        env: Some("LTR_TLS_FINGERPRINT"),
        default: None,
        help: "SHA-256 fingerprint of the remote TLS certificate",
    },
    KeySpec {
        name: "tls-server-name",
        kind: Kind::Str,
        env: Some("LTR_TLS_SERVER_NAME"),
        default: None,
        help: "TLS server name; defaults to --to",
    },
    KeySpec {
        name: "tls-client-cert",
        kind: Kind::Path,
        env: Some("LTR_TLS_CLIENT_CERT"),
        default: None,
        help: "Client certificate PEM for mutual tunnel TLS",
    },
    KeySpec {
        name: "tls-client-key",
        kind: Kind::Path,
        env: Some("LTR_TLS_CLIENT_KEY"),
        default: None,
        help: "Client private key PEM for mutual tunnel TLS",
    },
    KeySpec {
        name: "min-port",
        kind: Kind::Port,
        env: Some("LTR_MIN_PORT"),
        default: Some("1024"),
        help: "Server: minimum accepted tunnel port",
    },
    KeySpec {
        name: "max-port",
        kind: Kind::Port,
        env: Some("LTR_MAX_PORT"),
        default: Some("65535"),
        help: "Server: maximum accepted tunnel port",
    },
    KeySpec {
        name: "bind-addr",
        kind: Kind::Ip,
        env: None,
        default: Some("0.0.0.0"),
        help: "Server: control bind address",
    },
    KeySpec {
        name: "bind-tunnels",
        kind: Kind::Ip,
        env: None,
        default: None,
        help: "Server: tunnel listener address; defaults to bind-addr",
    },
    KeySpec {
        name: "tls-cert",
        kind: Kind::Path,
        env: Some("LTR_TLS_CERT"),
        default: None,
        help: "Server: PEM certificate overriding the generated one",
    },
    KeySpec {
        name: "tls-key",
        kind: Kind::Path,
        env: Some("LTR_TLS_KEY"),
        default: None,
        help: "Server: PEM private key for tunnel TLS",
    },
    KeySpec {
        name: "tls-client-ca",
        kind: Kind::Path,
        env: Some("LTR_TLS_CLIENT_CA"),
        default: None,
        help: "Server: CA PEM requiring client certificates",
    },
];

/// Looks up a key specification by name.
pub fn key_spec(name: &str) -> Option<&'static KeySpec> {
    KEYS.iter().find(|spec| spec.name == name)
}

/// The parsed config file.
#[derive(Debug, Clone, Default)]
pub struct FileConfig {
    entries: BTreeMap<String, String>,
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
        let tmp = path.with_extension("toml.tmp");
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("could not create {}", tmp.display()))?;
            file.write_all(raw.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, raw.as_bytes())
                .with_context(|| format!("could not create {}", tmp.display()))?;
        }
        fs::rename(&tmp, path).with_context(|| format!("could not replace {}", path.display()))?;
        Ok(())
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValue {
    /// The effective value.
    pub value: String,
    /// The layer that provided it.
    pub source: Source,
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
}
