//! keyring 4.x facade variant: Secret Service only on Linux (zbus store).
use keyring::Entry;
use std::process::exit;

fn main() {
    let name = format!("hm-x4-{:x}", std::process::id());
    let secret = format!(
        "{:x}{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let r = (|| -> Result<(bool, bool), String> {
        let e = Entry::new("heimdall-x4", &name).map_err(|e| e.to_string())?;
        e.set_password(&secret).map_err(|e| e.to_string())?;
        let ok = e.get_password().map_err(|e| e.to_string())? == secret;
        e.delete_credential().map_err(|e| e.to_string())?;
        let gone = matches!(e.get_password(), Err(keyring::Error::NoEntry));
        Ok((ok, gone))
    })();
    match r {
        Ok((m, g)) => {
            println!(
                "{{\"backend\":\"secret-service(keyring-facade)\",\"lang\":\"rust\",\"match\":{m},\"gone\":{g}}}"
            );
            if !(m && g) {
                exit(1)
            }
        }
        Err(e) => {
            println!(
                "{{\"backend\":\"secret-service(keyring-facade)\",\"lang\":\"rust\",\"err\":{:?}}}",
                e
            );
            exit(1)
        }
    }
}
