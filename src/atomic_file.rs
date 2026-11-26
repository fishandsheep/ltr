//! Small helpers for safely publishing files through private temporary files.

use std::{fs, io, path::Path};

use uuid::Uuid;

/// Writes a new file without replacing an existing path, then syncs its data.
pub(crate) fn write_new(path: &Path, contents: &[u8], mode: Option<u32>) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }

    let mut file = options.open(path)?;
    if let Err(err) = std::io::Write::write_all(&mut file, contents).and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(err);
    }
    Ok(())
}

/// Writes and syncs a unique temporary file, then atomically publishes it.
pub(crate) fn write_atomic(path: &Path, contents: &[u8], mode: Option<u32>) -> io::Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = write_new(&tmp, contents, mode).and_then(|()| fs::rename(&tmp, path));
    if let Err(err) = result {
        let _ = fs::remove_file(tmp);
        return Err(err);
    }
    sync_parent_dir(path);
    Ok(())
}

/// Syncs the directory so the rename itself survives a crash. Best effort: the
/// new contents are already published, so reporting failure here would make
/// callers roll back memory that the file now matches.
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}
