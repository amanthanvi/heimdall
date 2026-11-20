//! WSL Mode B's transport (ADR-0010 §3 items 3–8, 11–12; design U4 §2–§4).
//!
//! * [`Bridge`] (in `session`) is the Windows side: one helper session serving one Mode B
//!   environment's endpoints. It starts the helper through a [`HelperLauncher`], says hello
//!   under U3a's rules, and then keeps the channel open: `realize` and `withdraw` calls go
//!   out, and each stream a Linux client opens on a binding's endpoint is handed to a
//!   [`StreamHandler`] (the runtime serves it with that binding's signer).
//! * `linux` is the helper's side: the per-binding directory and socket, the admission checks,
//!   the stream relay.
//!
//! The runtime owns the supervision of a [`Bridge`] (when it starts, the running re-check,
//! respawn): this crate only moves bytes and files.
//!
//! [`HelperLauncher`]: crate::client::HelperLauncher

pub(crate) mod session;

#[cfg(unix)]
pub(crate) mod linux;

/// The helper's Mode B side off Unix: nothing serves it (the helper runs on Linux only), so a
/// request is answered `unsupported`.
#[cfg(not(unix))]
pub(crate) mod linux {
    use std::path::PathBuf;

    use crate::helper::{Broken, FrameWriter, HelperEnv};
    use crate::proto::{ErrorKind, HelperFrame, WindowsFrame};

    pub(crate) struct Endpoints {
        writer: FrameWriter,
        run: PathBuf,
    }

    impl Endpoints {
        pub(crate) fn new(env: &HelperEnv, writer: FrameWriter) -> Self {
            Endpoints {
                writer,
                run: env.state_base.join("heimdall").join("run"),
            }
        }

        pub(crate) fn run_dir(&self) -> String {
            self.run.to_string_lossy().into_owned()
        }

        pub(crate) fn handle(&mut self, frame: WindowsFrame) -> Result<(), Broken> {
            let id = match frame {
                WindowsFrame::Realize { id, .. }
                | WindowsFrame::Withdraw { id, .. }
                | WindowsFrame::Realized { id } => id,
                _ => return Err(Broken::Protocol),
            };
            self.writer
                .send(&HelperFrame::Error {
                    id,
                    kind: ErrorKind::Unsupported,
                    message: "mode b runs on linux only".to_owned(),
                })
                .map_err(|_| Broken::Gone)
        }

        pub(crate) fn shutdown(&mut self) {}
    }
}

pub use session::{Bridge, BridgePublic, Realized, StreamHandler, realized_paths};
