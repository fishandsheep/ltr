//! Self-update (`ltr update`): detects the install channel and updates the
//! binary in place.
//!
//! - npm installs (`node_modules/@qinshower/...`) are told to update through
//!   npm so the package manager stays authoritative.
//! - cargo installs (`~/.cargo/bin`) are told to update through cargo.
//! - everything else downloads the matching GitHub Release archive, verifies
//!   its sha256, and atomically replaces the running executable.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

/// GitHub repository that serves releases.
const DEFAULT_REPO: &str = "fishandsheep/ltr";
const MAX_RELEASE_METADATA: usize = 2 * 1024 * 1024;
const MAX_CHECKSUM_FILE: usize = 4096;
const MAX_ARCHIVE_SIZE: usize = 128 * 1024 * 1024;
const MAX_BINARY_SIZE: usize = 128 * 1024 * 1024;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveFormat {
    TarGz,
    Zip,
}

impl ArchiveFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::Zip => "zip",
        }
    }

    fn executable(self) -> &'static str {
        match self {
            Self::TarGz => "ltr",
            Self::Zip => "ltr.exe",
        }
    }
}

/// Maps an OS/architecture pair to its published release asset layout.
fn release_target(os: &str, arch: &str) -> Option<(&'static str, ArchiveFormat)> {
    match (os, arch) {
        ("linux", "x86_64") => Some(("x86_64-unknown-linux-musl", ArchiveFormat::TarGz)),
        ("macos", "aarch64") => Some(("aarch64-apple-darwin", ArchiveFormat::TarGz)),
        ("windows", "x86_64") => Some(("x86_64-pc-windows-msvc", ArchiveFormat::Zip)),
        _ => None,
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

async fn get_bytes(client: &reqwest::Client, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    match reqwest::Url::parse(url) {
        Ok(parsed) if parsed.scheme() == "https" => {}
        _ => bail!("refusing non-HTTPS update URL"),
    }
    let response = client
        .get(url)
        .header("User-Agent", "ltr-update")
        .send()
        .await
        .with_context(|| format!("could not fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("request failed for {url}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("update response exceeds the allowed size limit");
    }
    let mut bytes = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            bail!("update response exceeds the allowed size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn github_flow(exe: &Path) -> Result<()> {
    let current = normalize_version(env!("CARGO_PKG_VERSION"));
    println!("ltr {current}: checking for updates...");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() == "https" {
                attempt.follow()
            } else {
                attempt.error("refusing non-HTTPS redirect")
            }
        }))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("could not create the update client")?;

    let release_json = get_bytes(
        &client,
        &format!("{}/releases/latest", api_base()),
        MAX_RELEASE_METADATA,
    )
    .await?;
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

    let (triple, format) = release_target(std::env::consts::OS, std::env::consts::ARCH)
        .context("this platform is not supported by the LTR release matrix")?;
    let asset_name = format!("ltr-{tag}-{triple}.{}", format.extension());
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
    let tarball = get_bytes(&client, &download_url, MAX_ARCHIVE_SIZE).await?;
    let checksum = get_bytes(
        &client,
        &format!("{download_url}.sha256"),
        MAX_CHECKSUM_FILE,
    )
    .await?;
    let expected_hash =
        parse_shasum(std::str::from_utf8(&checksum).context("sha256 file is not UTF-8")?)?;
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

    let binary = extract_binary(&tarball, format)?;
    replace_executable(exe, &binary)?;
    println!("Updated ltr {current} -> {latest}.");
    println!("Running instances keep the old binary until restarted (see `ltr -l`).");
    Ok(())
}

/// Pulls the platform executable out of a GitHub release archive.
fn extract_binary(archive_bytes: &[u8], format: ArchiveFormat) -> Result<Vec<u8>> {
    match format {
        ArchiveFormat::TarGz => {
            let decoder = flate2::read::GzDecoder::new(archive_bytes);
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
                if path == Path::new(format.executable()) && entry.header().entry_type().is_file() {
                    return read_limited(&mut entry);
                }
            }
        }
        ArchiveFormat::Zip => {
            let cursor = std::io::Cursor::new(archive_bytes);
            let mut archive =
                zip::ZipArchive::new(cursor).context("could not read the release ZIP archive")?;
            for index in 0..archive.len() {
                let mut entry = archive
                    .by_index(index)
                    .context("could not read a release ZIP entry")?;
                if entry.name() == format.executable()
                    && entry
                        .unix_mode()
                        .is_none_or(|mode| mode & 0o170000 != 0o120000)
                {
                    return read_limited(&mut entry);
                }
            }
        }
    }
    bail!("release archive contains no {} binary", format.executable());
}

fn read_limited(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BINARY_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .context("could not extract the executable")?;
    if bytes.len() > MAX_BINARY_SIZE {
        bail!("executable in release archive exceeds the allowed size limit");
    }
    Ok(bytes)
}

/// Atomically replaces the executable at `exe` with `binary`.
fn replace_executable(exe: &Path, binary: &[u8]) -> Result<()> {
    let nonce = uuid::Uuid::new_v4();
    let staged: PathBuf = exe.with_extension(format!("{nonce}.ltr-new"));
    stage_binary(&staged, binary)?;

    #[cfg(unix)]
    let result = std::fs::rename(&staged, exe)
        .with_context(|| format!("could not replace {} with the new binary", exe.display()));

    #[cfg(not(unix))]
    let result = {
        let old = exe.with_extension(format!("{nonce}.ltr-old"));
        match std::fs::rename(exe, &old) {
            Err(err) => Err(err).with_context(|| {
                format!(
                    "could not move {} while it is running; retry after stopping ltr",
                    exe.display()
                )
            }),
            Ok(()) => match std::fs::rename(&staged, exe) {
                Ok(()) => {
                    let _ = std::fs::remove_file(old);
                    Ok(())
                }
                Err(err) => match std::fs::rename(&old, exe) {
                    Ok(()) => Err(err).with_context(|| {
                        format!("could not replace {} with the new binary", exe.display())
                    }),
                    Err(restore_err) => anyhow::bail!(
                        "could not replace {}; the previous executable remains at {}: {} (restore failed: {})",
                        exe.display(),
                        old.display(),
                        err,
                        restore_err
                    ),
                },
            },
        }
    };

    if result.is_err() {
        let _ = std::fs::remove_file(staged);
    }
    result
}

fn stage_binary(path: &Path, binary: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o755);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("could not stage {}", path.display()))?;
    if let Err(err) = file.write_all(binary).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(err)
            .with_context(|| format!("could not write staged binary {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        detect_channel, extract_binary, is_newer, normalize_version, parse_shasum, release_target,
        replace_executable, stage_binary, ArchiveFormat, Channel,
    };

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
    fn release_targets_match_published_archive_formats() {
        assert_eq!(
            release_target("windows", "x86_64"),
            Some(("x86_64-pc-windows-msvc", ArchiveFormat::Zip))
        );
        assert_eq!(
            release_target("macos", "aarch64"),
            Some(("aarch64-apple-darwin", ArchiveFormat::TarGz))
        );
        assert_eq!(
            release_target("linux", "x86_64"),
            Some(("x86_64-unknown-linux-musl", ArchiveFormat::TarGz))
        );
        assert_eq!(release_target("macos", "x86_64"), None);
        assert_eq!(release_target("linux", "aarch64"), None);
        assert_eq!(release_target("freebsd", "x86_64"), None);
    }

    #[test]
    fn extracts_windows_executable_from_release_zip() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut cursor);
            archive
                .start_file("ltr.exe", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut archive, b"windows executable").unwrap();
            archive.finish().unwrap();
        }

        assert_eq!(
            extract_binary(cursor.get_ref(), ArchiveFormat::Zip).unwrap(),
            b"windows executable"
        );
    }

    #[test]
    fn staging_does_not_overwrite_an_existing_path() {
        let path = std::env::temp_dir().join(format!("ltr-stage-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"existing").unwrap();

        assert!(stage_binary(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn replacement_installs_the_staged_binary() {
        let path = std::env::temp_dir().join(format!("ltr-update-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"old binary").unwrap();

        replace_executable(&path, b"new binary").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new binary");
        std::fs::remove_file(path).unwrap();
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
