use std::{
    env, fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use rcgen::generate_simple_self_signed;
use uuid::Uuid;

use super::state::WebTlsConfig;

pub(crate) fn load_or_generate_at(path: &Path, explicit: Option<String>) -> Result<String> {
    if let Some(token) = explicit
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
    {
        return Ok(token);
    }

    if let Ok(token) = fs::read_to_string(path) {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_string());
        }
    }

    let token = Uuid::new_v4().to_string();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create Web data directory {}", parent.display()))?;
    }

    match create_private_file(path, &token) {
        Ok(()) => Ok(token),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let existing = fs::read_to_string(path)
                .with_context(|| format!("could not read Web token {}", path.display()))?;
            let existing = existing.trim().to_string();
            if existing.is_empty() {
                bail!("Web token file {} is empty", path.display());
            }
            Ok(existing)
        }
        Err(err) => {
            Err(err).with_context(|| format!("could not save Web token {}", path.display()))
        }
    }
}

pub(crate) fn load_or_generate(explicit: Option<String>) -> Result<String> {
    load_or_generate_at(&web_token_path()?, explicit)
}

pub(crate) fn web_token_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("web-token"))
}

pub(crate) fn web_tls_paths() -> Result<(PathBuf, PathBuf)> {
    let data_dir = data_dir()?;
    Ok((data_dir.join("web-cert.pem"), data_dir.join("web-key.pem")))
}

pub(crate) fn load_or_generate_tls(
    server_host: &str,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<WebTlsConfig> {
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => Ok(WebTlsConfig {
            cert_pem: fs::read(cert_path).with_context(|| {
                format!("could not read Web certificate {}", cert_path.display())
            })?,
            key_pem: fs::read(key_path).with_context(|| {
                format!("could not read Web private key {}", key_path.display())
            })?,
        }),
        (Some(_), None) | (None, Some(_)) => {
            bail!("--web-cert and --web-key must be provided together")
        }
        (None, None) => {
            let (cert_path, key_path) = web_tls_paths()?;
            let data_dir = cert_path
                .parent()
                .context("Web certificate path has no parent directory")?;
            if cert_path.exists() != key_path.exists() {
                bail!(
                    "Web certificate state is incomplete; provide --web-cert and --web-key together or remove {}",
                    data_dir.display()
                );
            }
            if cert_path.exists() && key_path.exists() {
                return Ok(WebTlsConfig {
                    cert_pem: fs::read(&cert_path).with_context(|| {
                        format!("could not read Web certificate {}", cert_path.display())
                    })?,
                    key_pem: fs::read(&key_path).with_context(|| {
                        format!("could not read Web private key {}", key_path.display())
                    })?,
                });
            }

            let names = vec![server_host.to_string(), "localhost".to_string()];
            let generated = generate_simple_self_signed(names)
                .context("could not generate a self-signed Web certificate")?;
            let config = WebTlsConfig {
                cert_pem: generated.cert.pem().into_bytes(),
                key_pem: generated.signing_key.serialize_pem().into_bytes(),
            };
            fs::create_dir_all(data_dir).with_context(|| {
                format!("could not create Web data directory {}", data_dir.display())
            })?;
            fs::write(&cert_path, &config.cert_pem).with_context(|| {
                format!("could not save Web certificate {}", cert_path.display())
            })?;
            write_private(&key_path, &config.key_pem).with_context(|| {
                format!("could not save Web private key {}", key_path.display())
            })?;
            Ok(config)
        }
    }
}

fn data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = env::var_os("LOCALAPPDATA").or_else(|| env::var_os("APPDATA"));

    #[cfg(target_os = "macos")]
    let base =
        env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"));

    #[cfg(all(unix, not(target_os = "macos")))]
    let base = env::var_os("XDG_DATA_HOME").or_else(|| {
        env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share").into_os_string())
    });

    let base = base.context("could not determine the user data directory")?;
    Ok(PathBuf::from(base).join("ltr"))
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, contents)
}

fn create_private_file(path: &Path, token: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, token.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use super::load_or_generate_at;

    #[test]
    fn generated_token_is_reused() {
        let root = std::env::temp_dir().join(format!(
            "ltr-web-token-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        ));
        let path = root.join("web-token");

        let first = load_or_generate_at(&path, None).expect("token should be generated");
        let second = load_or_generate_at(&path, None).expect("token should be loaded");

        assert!(!first.is_empty());
        assert_eq!(first, second);
        assert_eq!(fs::read_to_string(&path).unwrap(), first);
        fs::remove_dir_all(root).unwrap();
    }
}
