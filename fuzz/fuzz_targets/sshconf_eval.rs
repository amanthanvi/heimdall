//! Boundary 1, the include walk and the evaluator: a root configuration and one included
//! file, both attacker-chosen, evaluated for a fixed query. Nothing is executed: the source
//! is in memory (`MemSource`), so a configuration's commands stay data.
#![no_main]
use std::path::PathBuf;

use heimdall_sshconf::eval::{Invocation, OpenSshVersion, Query, evaluate};
use heimdall_sshconf::include::{ConfigSet, MemSource, Roots};
use heimdall_sshconf::limits::Limits;
use libfuzzer_sys::fuzz_target;

const ROOT: &str = "/hm/home/.ssh/config";

fuzz_target!(|data: &[u8]| {
    let cut = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    let (root, rest) = data.split_at(cut);
    let included = rest.get(1..).unwrap_or(&[]);
    let src = MemSource::new("/hm/home", "/hm/home/.ssh", "/hm/etc/ssh")
        .with_file(ROOT, root.to_vec())
        .with_file("/hm/home/.ssh/conf.d/a.conf", included.to_vec())
        .with_file("/hm/etc/ssh/ssh_config", b"Host *\n  SendEnv LANG\n".to_vec());
    let roots = Roots::new(Some(PathBuf::from(ROOT)), Some(PathBuf::from("/hm/etc/ssh/ssh_config")));
    let query = Query {
        host: "box".to_owned(),
        user: None,
        local_user: Some("fixture".to_owned()),
        client_version: OpenSshVersion { major: 10, minor: 3, portable: Some(1) },
        invocation: Invocation::Shell,
    };
    let _ = evaluate(&mut ConfigSet::new(), &src, &roots, &query, &Limits::default());
});
