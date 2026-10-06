//! X4 Linux spike (Rust): store, read, delete a secret via freedesktop Secret
//! Service (D-Bus, pure-Rust zbus) and the kernel keyring. Disposable G02 evidence.
use std::io::Read;
use std::process::exit;
use std::time::Duration;

mod backends;

/// store -> read -> delete -> gone, per backend.
pub trait Backend {
    fn store(&self, name: &str, secret: &[u8]) -> Result<(), String>;
    fn read(&self, name: &str) -> Result<Vec<u8>, String>;
    fn del(&self, name: &str) -> Result<(), String>;
    fn gone(&self, name: &str) -> Result<bool, String>;
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .expect("urandom");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn jstr(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push(' '),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    // Watchdog: a locked collection can make Secret Service block on a prompt.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(20));
        eprintln!("timeout");
        exit(124);
    });
    let Some((b, label)) = backends::pick(&arg) else {
        eprintln!("unknown or unavailable backend");
        exit(2);
    };
    let secret = rand_hex(24).into_bytes();
    let name = format!("hm-x4-{}", rand_hex(4));
    let (mut store, mut read, mut del) = ("skip", "skip", "skip");
    let (mut matched, mut gone, mut err) = (false, false, String::new());
    match b.store(&name, &secret) {
        Err(e) => {
            store = "fail";
            err = e;
        }
        Ok(()) => {
            store = "ok";
            match b.read(&name) {
                Ok(v) => {
                    read = "ok";
                    matched = ct_eq(&v, &secret);
                }
                Err(e) => {
                    read = "fail";
                    err = e;
                }
            }
            match b.del(&name) {
                Ok(()) => {
                    del = "ok";
                    match b.gone(&name) {
                        Ok(g) => gone = g,
                        Err(e) => err = e,
                    }
                }
                Err(e) => {
                    del = "fail";
                    err = e;
                }
            }
        }
    }
    let e = if err.is_empty() {
        String::new()
    } else {
        format!(",\"err\":{}", jstr(&err))
    };
    println!(
        "{{\"backend\":{},\"lang\":\"rust\",\"store\":\"{store}\",\"read\":\"{read}\",\"match\":{matched},\"delete\":\"{del}\",\"gone\":{gone}{e}}}",
        jstr(label)
    );
    if !(store == "ok" && read == "ok" && matched && del == "ok" && gone) {
        exit(1);
    }
}
