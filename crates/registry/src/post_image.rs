//! Post-image construction and the post-write checks (ADR-0008 D5 §6.3, §6.8; m03-plan
//! U5): [`post_image_without`], [`check_post_append`], [`check_post_remove`].
//!
//! ⟨wave 4, round 2⟩ **Digest forms** (ADR-0008 §17.21 item 4): the runtime never
//! stores an inspected registry's foreign bytes, so the checks also take the image
//! by its length and SHA-256 ([`ImageDigest`]); "starts with the image" is then
//! "the first `len` bytes hash to it", which a different prefix cannot meet.
//!
//! **Byte-preserving.** A registry is split into lines at `\n` only
//! ([`crate::line::lines`]); a line's bytes are everything up to its `\n`, so a `\r`
//! (CRLF), a BOM, comments, options and trailing spaces are part of the line they are
//! on. Removing a line removes its bytes and its own `\n` (if it has one), nothing
//! else: every other byte of the preimage is kept, in order. A line "equal to our
//! line" is byte-for-byte equal; a near-duplicate (another principal, a trailing
//! space, a `\r`) is a different line.
//!
//! A line **containing the marker** but not equal to our line makes
//! [`post_image_without`] refuse: the removal never rewrites a line it did not write
//! (`held`, `registry_line_damaged`; D5 §6.8 step 2).

use heimdall_domain::enrollment::HoldReason;

use heimdall_domain::projection::Sha256Hex;

use crate::line::{contains, marker_lines, marker_of};

/// A registry image kept by its length and SHA-256 only (§17.21 item 4: the
/// journal never stores another key's line or a comment).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageDigest {
    /// The image's length in bytes.
    pub len: u64,
    /// Its SHA-256.
    pub sha256: Sha256Hex,
}

impl ImageDigest {
    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> ImageDigest {
        ImageDigest {
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256: Sha256Hex::of(bytes),
        }
    }

    /// Whether `bytes` starts with the image (or equals it).
    #[must_use]
    pub fn is_prefix_of(&self, bytes: &[u8]) -> bool {
        usize::try_from(self.len)
            .ok()
            .and_then(|n| bytes.get(..n))
            .is_some_and(|head| Sha256Hex::of(head) == self.sha256)
    }
}

/// Why no post-image was built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PostImageError {
    /// The expected line carries no valid marker.
    #[error("the expected registry line has no valid marker")]
    InvalidLine,
    /// These lines (1-based) contain the marker but differ from our line.
    #[error("registry lines {line_numbers:?} contain the marker but differ from the line")]
    MarkerLineDiffers {
        /// The 1-based line numbers.
        line_numbers: Vec<usize>,
    },
}

/// Why a post-write check failed (the record goes `held`; D5 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum PostWriteError {
    /// The expected line carries no valid marker.
    #[error("the expected registry line has no valid marker")]
    InvalidLine,
    /// After an append: not exactly one marker line, or it differs from our line.
    #[error("after the append {marker_lines} lines contain the marker, or ours differs")]
    LineDamaged {
        /// Lines containing the marker.
        marker_lines: usize,
    },
    /// After an append: the content without our line neither equals nor starts with
    /// the inspected preimage.
    #[error("the registry changed concurrently with the append")]
    PreimageChanged,
    /// After a removal: a line still contains the marker.
    #[error("after the removal {marker_lines} lines still contain the marker")]
    MarkerPresent {
        /// Lines containing the marker.
        marker_lines: usize,
    },
    /// After a removal: the content neither equals nor starts with the post-image.
    #[error("the registry changed concurrently with the removal")]
    PostImageChanged,
}

impl PostWriteError {
    /// The hold reason the record gets.
    #[must_use]
    pub fn hold_reason(self) -> HoldReason {
        match self {
            PostWriteError::LineDamaged { .. } | PostWriteError::MarkerPresent { .. } => {
                HoldReason::RegistryLineDamaged
            }
            PostWriteError::InvalidLine
            | PostWriteError::PreimageChanged
            | PostWriteError::PostImageChanged => HoldReason::PostWriteCheckFailed,
        }
    }
}

/// `preimage` minus exactly the lines equal to `line` (D5 §6.8 step 2). Every other
/// byte is kept in order. A preimage without our line is returned unchanged.
///
/// # Errors
/// [`PostImageError::MarkerLineDiffers`] when a line contains the marker but is not
/// `line`; [`PostImageError::InvalidLine`] when `line` has no valid marker.
pub fn post_image_without(preimage: &[u8], line: &str) -> Result<Vec<u8>, PostImageError> {
    let marker = marker_of(line).ok_or(PostImageError::InvalidLine)?;
    let mut out = Vec::with_capacity(preimage.len());
    let mut differing = Vec::new();
    for (index, piece) in preimage.split_inclusive(|b| *b == b'\n').enumerate() {
        let body = piece.strip_suffix(b"\n").unwrap_or(piece);
        if body == line.as_bytes() {
            continue;
        }
        if contains(body, marker.as_bytes()) {
            differing.push(index + 1);
        }
        out.extend_from_slice(piece);
    }
    if differing.is_empty() {
        Ok(out)
    } else {
        Err(PostImageError::MarkerLineDiffers {
            line_numbers: differing,
        })
    }
}

/// The post-write check after `append`, from its reported content `post` (D5 §6.3):
/// exactly one line contains the marker and equals `line` byte for byte, and the
/// content without it equals the inspected preimage `pre` or starts with it (an
/// administrator append landing after ours is allowed).
///
/// # Errors
/// [`PostWriteError`]: `LineDamaged`, `PreimageChanged` or `InvalidLine`.
pub fn check_post_append(pre: &[u8], post: &[u8], line: &str) -> Result<(), PostWriteError> {
    post_append(|without| without.starts_with(pre), post, line)
}

/// [`check_post_append`] with the inspected preimage by its digest.
///
/// # Errors
/// As [`check_post_append`].
pub fn check_post_append_digest(
    pre: &ImageDigest,
    post: &[u8],
    line: &str,
) -> Result<(), PostWriteError> {
    post_append(|without| pre.is_prefix_of(without), post, line)
}

fn post_append(
    starts_with_pre: impl Fn(&[u8]) -> bool,
    post: &[u8],
    line: &str,
) -> Result<(), PostWriteError> {
    let marker = marker_of(line).ok_or(PostWriteError::InvalidLine)?;
    let count = marker_lines(post, marker);
    if count != 1 {
        return Err(PostWriteError::LineDamaged {
            marker_lines: count,
        });
    }
    let without = post_image_without(post, line).map_err(|_| PostWriteError::LineDamaged {
        marker_lines: count,
    })?;
    if without.len() == post.len() {
        // The one marker line is not ours.
        return Err(PostWriteError::LineDamaged {
            marker_lines: count,
        });
    }
    if starts_with_pre(&without) {
        Ok(())
    } else {
        Err(PostWriteError::PreimageChanged)
    }
}

/// The post-write check after `remove`, from its reported content `post` (D5 §6.3):
/// no line contains `marker`, and the content equals `post_image` or starts with it
/// (a later administrator append).
///
/// # Errors
/// [`PostWriteError::MarkerPresent`] or [`PostWriteError::PostImageChanged`].
pub fn check_post_remove(
    post_image: &[u8],
    post: &[u8],
    marker: &str,
) -> Result<(), PostWriteError> {
    post_remove(post.starts_with(post_image), post, marker)
}

/// [`check_post_remove`] with the post-image by its digest.
///
/// # Errors
/// As [`check_post_remove`].
pub fn check_post_remove_digest(
    post_image: &ImageDigest,
    post: &[u8],
    marker: &str,
) -> Result<(), PostWriteError> {
    post_remove(post_image.is_prefix_of(post), post, marker)
}

fn post_remove(starts_with_image: bool, post: &[u8], marker: &str) -> Result<(), PostWriteError> {
    let count = marker_lines(post, marker);
    if count != 0 {
        return Err(PostWriteError::MarkerPresent {
            marker_lines: count,
        });
    }
    if starts_with_image {
        Ok(())
    } else {
        Err(PostWriteError::PostImageChanged)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const LINE: &str = "cert-authority,principals=\"hm:d:a\" ssh-ed25519 AAAA heimdall:enr_1";

    #[test]
    fn removes_only_exact_lines() {
        let pre = format!("\u{feff}# c\r\nopt,x {LINE}x\nA\n{LINE}\nB");
        assert!(matches!(
            post_image_without(pre.as_bytes(), LINE),
            Err(PostImageError::MarkerLineDiffers { line_numbers }) if line_numbers == [2]
        ));
        let pre = format!("\u{feff}# c\r\nA\n{LINE}\nB");
        assert_eq!(
            post_image_without(pre.as_bytes(), LINE).unwrap(),
            "\u{feff}# c\r\nA\nB".as_bytes()
        );
        let pre = format!("A\n{LINE}");
        assert_eq!(post_image_without(pre.as_bytes(), LINE).unwrap(), b"A\n");
    }

    #[test]
    fn append_check() {
        let pre = b"A\nB";
        let post = format!("A\nB\n{LINE}\nC\n");
        assert_eq!(check_post_append(pre, post.as_bytes(), LINE), Ok(()));
        let joined = format!("A\nB\nC{LINE}\n");
        assert!(matches!(
            check_post_append(pre, joined.as_bytes(), LINE),
            Err(PostWriteError::LineDamaged { .. })
        ));
        let lost = format!("A\n{LINE}\n");
        assert_eq!(
            check_post_append(pre, lost.as_bytes(), LINE),
            Err(PostWriteError::PreimageChanged)
        );
        assert_eq!(
            check_post_remove(b"A\n", b"A\nX\n", "heimdall:enr_1"),
            Ok(())
        );
        assert_eq!(
            check_post_remove(b"A\nB\n", b"A\n", "heimdall:enr_1"),
            Err(PostWriteError::PostImageChanged)
        );
    }

    /// ⟨round 2⟩ §17.21 item 4: the digest forms agree with the byte forms.
    #[test]
    fn digest_checks_agree_with_byte_checks() {
        let pre = b"# owner note\nssh-ed25519 BBBB other\n".to_vec();
        let pre_d = ImageDigest::of(&pre);
        let post = [pre.clone(), format!("{LINE}\n").into_bytes()].concat();
        assert_eq!(check_post_append_digest(&pre_d, &post, LINE), Ok(()));
        assert_eq!(check_post_append(&pre, &post, LINE), Ok(()));
        let later = [post.clone(), b"admin\n".to_vec()].concat();
        assert_eq!(check_post_append_digest(&pre_d, &later, LINE), Ok(()));
        let changed = [
            b"# other note\nssh-ed25519 BBBB other\n".to_vec(),
            format!("{LINE}\n").into_bytes(),
        ]
        .concat();
        assert_eq!(
            check_post_append_digest(&pre_d, &changed, LINE),
            Err(PostWriteError::PreimageChanged)
        );
        assert_eq!(
            check_post_append(&pre, &changed, LINE),
            Err(PostWriteError::PreimageChanged)
        );
        let image = ImageDigest::of(b"A\n");
        assert_eq!(
            check_post_remove_digest(&image, b"A\nB\n", "heimdall:enr_1"),
            Ok(())
        );
        assert_eq!(
            check_post_remove_digest(&ImageDigest::of(b"A\nB\n"), b"A\n", "heimdall:enr_1"),
            Err(PostWriteError::PostImageChanged)
        );
        assert!(!ImageDigest::of(b"AB").is_prefix_of(b"A"));
        assert!(ImageDigest::of(b"").is_prefix_of(b"anything"));
    }
}
