//! Boundary 2: Git configuration bytes read by the block scanner.
#![no_main]
use heimdall_sshconf::gitedit::{find_blocks, scan};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = scan(data);
    let _ = find_blocks(data);
});
