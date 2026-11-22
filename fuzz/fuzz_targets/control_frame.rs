//! Boundary 4: control-endpoint frames, decoded as the client and the server message types.
#![no_main]
use heimdall_contract::ipc::{ClientMessage, MAX_CONTROL_FRAME_BYTES, ServerMessage};
use heimdall_ipc::decode_frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_frame::<ClientMessage>(data, MAX_CONTROL_FRAME_BYTES);
    let _ = decode_frame::<ServerMessage>(data, MAX_CONTROL_FRAME_BYTES);
    let _ = decode_frame::<serde_json::Value>(data, MAX_CONTROL_FRAME_BYTES);
});
