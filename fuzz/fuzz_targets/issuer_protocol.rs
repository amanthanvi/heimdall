//! Boundary 8: issuer protocol frames, both directions.
#![no_main]
use heimdall_issuer::protocol::{Request, Response, split_frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Request::decode(data);
    let _ = Response::decode(data);
    if let Ok(Some((body, _))) = split_frame(data) {
        let _ = Request::decode(body);
        let _ = Response::decode(body);
    }
});
