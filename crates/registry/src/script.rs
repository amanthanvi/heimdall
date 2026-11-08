//! The remote scripts `inspect`, `bootstrap`, `append`, `remove` and `fence`
//! (ADR-0008 D5 §6.3; m03-plan U5 `registry::script`): one function `hm_main` called
//! on the last line, `export LC_ALL=C` and `umask 077` first, values as validated
//! single-quoted literals, the shared `/proc/<pid>/stat` `awk` text on Linux. The
//! goldens live in `tests/contracts/golden/enroll-scripts/`.
//!
//! U5 fills this module. Wave 0 freezes no item here: the script exit codes and the
//! HM1 output grammar are frozen in [`crate::hm1`].
