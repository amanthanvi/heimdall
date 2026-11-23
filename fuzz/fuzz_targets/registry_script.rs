//! Boundary 7, the registry script's inputs: the values that are placed into the remote
//! shell script (a registry path, a marker, a registry line, a step token). Each parser
//! must refuse anything that could change the script, so each is fed arbitrary text; the
//! line parser is also fed lines under every marker the marker parser accepts.
#![no_main]
use heimdall_registry::script::{Marker, RegistryLine, RegistryPath, StepToken};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (first, rest) = text.split_once('\n').unwrap_or((text, ""));
    let _ = RegistryPath::parse(first);
    let _ = StepToken::parse(first);
    if let Ok(marker) = Marker::parse(first) {
        let _ = RegistryLine::parse(rest, &marker);
    }
    let _ = RegistryPath::parse(rest);
    let _ = StepToken::parse(rest);
});
