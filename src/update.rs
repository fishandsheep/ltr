//! Self-update (`ltr update`): detects the install channel and updates the
//! binary in place.
//!
//! - npm installs (`node_modules/@qinshower/...`) are told to update through
//!   npm so the package manager stays authoritative.
//! - cargo installs (`~/.cargo/bin`) are told to update through cargo.
//! - everything else downloads the matching `ltr-<tag>-<target>.tar.gz` from
//!   GitHub Releases, verifies its sha256, and atomically replaces the
//!   running executable.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

/// GitHub repository that serves releases.
const DEFAULT_REPO: &str = "fishandsheep/ltr";

/// How this binary was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Installed through the `@qinshower/ltr` npm package.
    Npm,
    /// Installed through cargo.
    Cargo,
    /// Anything else: update from GitHub Releases.
    GitHub,
}

/// Detects the install channel from the executable location.
pub fn detect_channel(exe: &Path) -> Channel {
    let path = exe.to_string_lossy();
    if path.contains("node_modules") && path.contains("@qinshower") {
        Channel::Npm
    } else if path.contains(".cargo") {
        Channel::Cargo
    } else {
        Channel::GitHub
    }
}

/// Strips a leading `v` from a release tag.
pub fn normalize_version(tag: &str) -> &str {
    tag.trim().trim_start_matches('v')
}

/// Returns true when `latest` is strictly newer than `current`, comparing
/// dot-separated numeric segments.
pub fn is_newer(latest: &str, current: &str) -> bool {
    let (latest, current) = (normalize_version(latest), normalize_version(current));
    let parse = |version: &str| {
        version
            .split('.')
            .map(|part| part.trim().parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let (latest, current) = (parse(latest), parse(current));
    let len = latest.len().max(current.len());
    for index in 0..len {
        let l = latest.get(index).copied().unwrap_or(0);
        let c = current.get(index).copied().unwrap_or(0);
        if l != c {
            return l > c;
        }
    }
    false
}

/// Parses the hash out of a `shasum -a 256` line ("<hash>  <file>").
pub fn parse_shasum(content: &str) -> Result<String> {
    let hash = content
        .split_whitespace()
        .next()
        .context("sha256 file is empty")?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("sha256 file does not contain a SHA-256 digest");
    }
    Ok(hash.to_lowercase())
}

/// Maps the running platform onto the release asset triple.
fn release_triple() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        (os, arch) => {
            // Not in the release matrix; best effort keeps the asset lookup
            // honest by failing with a clear name.
            let _ = (os, arch);
            "unsupported-target"
        }
    }
}

/// Runs the update flow.
pub async fn run() -> Result<()> {
    // reqwest is built provider-less; install the tree's provider once.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let exe = std::env::current_exe().context("could not locate the running executable")?;
    match detect_channel(&exe) {
        Channel::Npm => {
            println!("ltr was installed through npm; update with:");
            println!("  npm install -g @qinshower/ltr");
            Ok(())
        }
        Channel::Cargo => {
            println!("ltr was installed through cargo; update with:");
            println!("  cargo install ltr-cli");
            Ok(())
        }
        Channel::GitHub => github_flow(&exe).await,
    }
}

fn api_base() -> String {
    let repo = std::env::var("LTR_UPDATE_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string());
    format!("https://api.github.com/repos/{repo}")
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .header("User-Agent", "ltr-update")
        .send()
        .await
        .with_context(|| format!("could not fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("request failed for {url}"))?;
    let mut bytes = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await? {
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn github_flow(exe: &Path) -> Result<()> {
    let current = normalize_version(env!("CARGO_PKG_VERSION"));
    println!("ltr {current}: checking for updates...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("could not create the update client")?;

    let release_json = get_bytes(&client, &format!("{}/releases/latest", api_base())).await?;
    let release: serde_json::Value =
        serde_json::from_slice(&release_json).context("could not parse the release metadata")?;
    let tag = release["tag_name"]
        .as_str()
        .context("release has no tag_name")?
        .to_string();
    let latest = normalize_version(&tag);
    if !is_newer(latest, current) {
        println!("ltr is up to date ({current}).");
        return Ok(());
    }

    let asset_name = format!("ltr-{tag}-{}.tar.gz", release_triple());
    let download_url = release["assets"]
        .as_array()
        .and_then(|assets| {
            assets
                .iter()
                .find(|asset| asset["name"].as_str() == Some(asset_name.as_str()))
                .and_then(|asset| asset["browser_download_url"].as_str())
        })
        .map(str::to_string)
        .with_context(|| format!("release {tag} has no asset {asset_name}"))?;

    println!("Downloading {asset_name}...");
    let tarball = get_bytes(&client, &download_url).await?;
    let expected_hash = parse_shasum(
        std::str::from_utf8(&get_bytes(&client, &format!("{download_url}.sha256")).await?)
            .with_context(|| "sha256 file is not UTF-8")?,
    )?;
    let actual_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&tarball);
        hex::encode(hasher.finalize())
    };
    if actual_hash != expected_hash {
        bail!("sha256 mismatch for {asset_name}: expected {expected_hash}, got {actual_hash}");
    }
    println!("Verified sha256 {actual_hash}.");

    let binary = extract_binary(&tarball)?;
    replace_executable(exe, &binary)?;
    println!("Updated ltr {current} -> {latest}.");
    println!("Running instances keep the old binary until restarted (see `ltr -l`).");
    Ok(())
}

/// Pulls the `ltr` member out of the release tarball.
fn extract_binary(tarball: &[u8]) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .context("could not read the release archive")?;
    for entry in entries {
        let mut entry = entry.context("could not read an archive entry")?;
        let path = entry
            .path()
            .context("archive entry has no path")?
            .to_path_buf();
        if path.file_name().and_then(|name| name.to_str()) == Some("ltr") {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .context("could not extract the ltr binary")?;
            return Ok(bytes);
        }
    }
    bail!("release archive contains no ltr binary");
}

/// Atomically replaces the executable at `exe` with `binary`.
fn replace_executable(exe: &Path, binary: &[u8]) -> Result<()> {
    let staged: PathBuf = exe.with_extension("ltr-new");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&staged)
            .with_context(|| format!("could not stage {}", staged.display()))?;
        file.write_all(binary)?;
        std::fs::rename(&staged, exe)
            .with_context(|| format!("could not replace {} with the new binary", exe.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&staged, binary)
            .with_context(|| format!("could not stage {}", staged.display()))?;
        let old = exe.with_extension("ltr-old");
        std::fs::rename(exe, &old).ok();
        match std::fs::rename(&staged, exe) {
            Ok(()) => Ok(()),
            Err(err) => {
                std::fs::rename(&old, exe).ok();
                Err(err).with_context(|| {
                    format!(
                        "could not replace {} while it is running; retry after stopping ltr",
                        exe.display()
                    )
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{detect_channel, is_newer, normalize_version, parse_shasum, Channel};

    #[test]
    fn version_comparison() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("1.2", "1.1.9"));
        assert!(!is_newer("1.1", "1.1.0"));
        assert_eq!(normalize_version(" v0.2.0 "), "0.2.0");
    }

    #[test]
    fn shasum_parsing() {
        let digest = "a".repeat(62) + "f0";
        let line = format!("{digest}  ltr-v0.2.0-x86_64-unknown-linux-musl.tar.gz\n");
        assert_eq!(parse_shasum(&line).unwrap(), digest);
        assert!(parse_shasum("").is_err());
        assert!(parse_shasum("zz zz").is_err());
    }

    #[test]
    fn channel_detection_by_path() {
        assert_eq!(
            detect_channel(Path::new(
                "/usr/lib/node_modules/@qinshower/ltr-darwin-arm64/bin/ltr"
            )),
            Channel::Npm
        );
        assert_eq!(
            detect_channel(Path::new("/home/user/.cargo/bin/ltr")),
            Channel::Cargo
        );
        assert_eq!(
            detect_channel(Path::new("/usr/local/bin/ltr")),
            Channel::GitHub
        );
    }
}
