//! Boundary 4, the streaming codec: the same bytes fed in attacker-chosen chunk sizes.
#![no_main]
use bytes::BytesMut;
use heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES;
use heimdall_ipc::session::BoundedFrameCodec;
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let Some((&step, body)) = data.split_first() else { return };
    let step = usize::from(step).max(1);
    let mut codec = BoundedFrameCodec::new(MAX_CONTROL_FRAME_BYTES);
    let mut buf = BytesMut::new();
    for chunk in body.chunks(step) {
        buf.extend_from_slice(chunk);
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
    let _ = codec.decode_eof(&mut buf);
});
