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
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
