//! ⟨M05; review M05-W4-R02, finding A29-F1⟩ Opening a file the user named on the command line,
//! or one in Heimdall's own configuration directory, without ever waiting on it.
//!
//! A FIFO with no writer blocks `open(2)` until a writer appears, so a byte bound applied to the
//! read comes too late. [`open_regular`] refuses anything but a regular file **before** it opens
//! the path (a symlink to a regular file still works: the check follows it, as the open does),
//! opens without blocking on Unix (`O_NONBLOCK | O_NOCTTY`: a FIFO swapped in after the check
//! opens at once), and checks the opened handle's type again, so what is read is a regular file
//! whatever happened in between. Callers keep their own byte bounds and parsing.

use std::fs::File;
use std::io;
use std::path::Path;

/// The error for a path that is not a regular file (`InvalidInput`); a missing path stays
/// `NotFound`, so a caller can still treat an absent optional file as absent.
fn not_regular() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "not a regular file")
}

/// Open `path` for reading if it is a regular file (module docs).
///
/// # Errors
/// `NotFound` when nothing is there, `InvalidInput` when it is not a regular file (a FIFO, a
/// device, a directory, a socket), any other open or `fstat` failure as it is.
pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
        options.custom_flags(i32::try_from(flags.bits()).unwrap_or_default());
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(not_regular());
    }
    Ok(file)
}

/// Whether `e` is [`open_regular`]'s refusal of a path that is not a regular file.
pub(crate) fn is_not_regular(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::InvalidInput
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A regular file and a symlink to one open; a directory is refused; a FIFO with no writer
    /// is refused at once instead of blocking (Unix).
    #[test]
    fn only_a_regular_file_opens_and_nothing_waits() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        assert!(open_regular(&file).is_ok());
        assert!(is_not_regular(&open_regular(dir.path()).unwrap_err()));
        assert_eq!(
            open_regular(&dir.path().join("absent")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        #[cfg(unix)]
        {
            let link = dir.path().join("link.txt");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(
                open_regular(&link).is_ok(),
                "a symlink to a regular file still opens"
            );
            let fifo = dir.path().join("fifo");
            heimdall_testkit::workspace::make_fifo(&fifo).unwrap();
            let started = std::time::Instant::now();
            assert!(is_not_regular(&open_regular(&fifo).unwrap_err()));
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
    }
}
