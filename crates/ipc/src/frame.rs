//! Length-prefixed JSON framing (ADR-0006 §2.2). `u32` big-endian length, then
//! exactly that many bytes of one UTF-8 JSON object. The limit is enforced before
//! allocation; an oversize or malformed frame closes the connection.

use heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES;
use tokio_util::codec::LengthDelimitedCodec;

/// Framing failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Declared length exceeds the limit.
    #[error("frame of {len} bytes exceeds limit {limit}")]
    TooLarge {
        /// Declared length.
        len: usize,
        /// Limit in force.
        limit: usize,
    },
    /// Payload is not valid UTF-8 JSON of the expected type.
    #[error("frame payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Underlying I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Peer closed before a complete frame.
    #[error("connection closed mid-frame")]
    Truncated,
}

/// Build the codec for an endpoint with the given frame limit.
#[must_use]
pub fn codec(max_frame_bytes: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_type::<u32>()
        .big_endian()
        .max_frame_length(max_frame_bytes)
        .new_codec()
}

/// Encode one message as a frame (pure; used by tests and both peers).
pub fn encode_frame<T: serde::Serialize>(
    msg: &T,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > max_frame_bytes {
        return Err(FrameError::TooLarge {
            len: body.len(),
            limit: max_frame_bytes,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        len: body.len(),
        limit: max_frame_bytes,
    })?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode one complete frame from `buf` (pure). Returns the message and the
/// number of bytes consumed, or `Ok(None)` when more bytes are needed.
pub fn decode_frame<T: serde::de::DeserializeOwned>(
    buf: &[u8],
    max_frame_bytes: usize,
) -> Result<Option<(T, usize)>, FrameError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > max_frame_bytes {
        return Err(FrameError::TooLarge {
            len,
            limit: max_frame_bytes,
        });
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let msg = serde_json::from_slice(&buf[4..4 + len])?;
    Ok(Some((msg, 4 + len)))
}

/// Default control-endpoint limit.
pub const CONTROL_LIMIT: usize = MAX_CONTROL_FRAME_BYTES;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_partial() {
        let v = serde_json::json!({"type": "hello", "n": 1});
        let bytes = encode_frame(&v, 1024).unwrap();
        assert_eq!(&bytes[..4], &(bytes.len() as u32 - 4).to_be_bytes());
        let (back, used): (serde_json::Value, usize) = decode_frame(&bytes, 1024).unwrap().unwrap();
        assert_eq!(back, v);
        assert_eq!(used, bytes.len());
        let partial: Option<(serde_json::Value, usize)> =
            decode_frame(&bytes[..bytes.len() - 1], 1024).unwrap();
        assert!(partial.is_none());
    }

    #[test]
    fn oversize_is_rejected_before_allocation() {
        let mut hdr = (u32::MAX).to_be_bytes().to_vec();
        hdr.extend_from_slice(b"xx");
        let r: Result<Option<(serde_json::Value, usize)>, _> = decode_frame(&hdr, 1024);
        assert!(matches!(r, Err(FrameError::TooLarge { .. })));
        let big = serde_json::Value::String("x".repeat(2000));
        assert!(matches!(
            encode_frame(&big, 1024),
            Err(FrameError::TooLarge { .. })
        ));
    }
}
