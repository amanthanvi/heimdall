# Enrollment script goldens

Empty until M03 U5 fills it (m03-plan U0, U5; ADR-0008 D5 §6.3).

U5 adds the generated remote scripts `inspect.sh`, `bootstrap.sh`, `append.sh`,
`remove.sh` and `fence.sh` (from `heimdall_registry::script`). Release builds
byte-compare the scripts they generate against these files; the test configuration
adds `HM_PAUSE <name>` points and is never compared here.

The HM1 output grammar and the script exit codes these scripts follow are frozen in
`crates/registry/src/hm1.rs`.
