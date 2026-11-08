# Windows launch drivers (M02-U8)

Native Windows drivers for the process contract of `heimdall run` (m02-plan U8; ADR-0007 §8
"Windows `run` spawns the child and waits"). They reuse the G02 round-4 approach in
`tests/native/windows-g02`: `G02X1Native.cs` (`X1Pty`, a pseudoconsole with the process
attached and no window; `ResizePseudoConsole`) and `Send-ConsoleCtrl.ps1` (a separate process
that attaches to the console and raises `CTRL_C_EVENT` or `CTRL_BREAK_EVENT`).

**Status: written and cross-checked, not run.** On the macOS build host the script parses
(`System.Management.Automation.Language.Parser`) and `G02X1Native.cs` compiles under PowerShell 7's
`Add-Type`; neither proves the Windows behaviour. Every row stays `blocked` on a native Windows 11
x64 host until U11's Windows run executes this driver (AGENTS.md: cross-compiles and emulation never
close a native claim). The driver has since run on the M02 Windows PC (ADR-0007 §12.44); see the
Ctrl-C disposition section below for what those runs showed.

| Row | m02-plan U8 test | Claim |
|---|---|---|
| `ctrlc.event` | `a27_ctrl_c_reaches_child_once` | `CTRL_C_EVENT` raised on the pseudoconsole by another process: the child (argvdump) counts exactly one interrupt; heimdall's console control guard consumed it (alive 600 ms later); heimdall exits with the child's 42 |
| `ctrlc.keystroke` | `a27_ctrl_c_reaches_child_once` | the same, with `^C` typed into the pseudoconsole input |
| `ctrlc.break` | (recorded) | the same for `CTRL_BREAK_EVENT` |
| `resize` | `a27_resize_reaches_child` | `ResizePseudoConsole` 100x30 → 132x40 reaches the child (a PowerShell poll of its console window size); heimdall exits with the child's 0 |

## Ctrl-C disposition (ADR-0007 §12.44 item 2)

Windows passes a process's "ignore Ctrl-C" attribute (`SetConsoleCtrlHandler(NULL, TRUE)`, or
`CREATE_NEW_PROCESS_GROUP`; bit 0 of `RTL_USER_PROCESS_PARAMETERS.ConsoleFlags`) on to every
process it creates, and a process that has it never sees `CTRL_C_EVENT`. Ctrl-Break cannot be
ignored that way. Agent and CI process environments often start the driver with the attribute set.
If heimdall inherited it, heimdall's child would inherit it too, and `ctrlc.event` and
`ctrlc.keystroke` would fail for a reason outside the product, while `ctrlc.break` still passed.
This was observed natively on the M02 Windows PC: the driver, heimdall and argvdump all had the
bit set, the child counted 0 interrupts, and the rows passed once the bit was cleared.

So the driver creates every heimdall with Ctrl-C processing restored. `X1Pty.ChildCtrlCProcessed`
calls `SetConsoleCtrlHandler(NULL, FALSE)` immediately before `CreateProcessW` and sets the
previous state again afterwards. The sender process (`Send-ConsoleCtrl.ps1`) still ignores the
event itself. Heimdall is transparent here: its child gets the disposition heimdall was created
with, which is what it would get if launched directly. The report records:

- `facts."ctrl-c-inherited"`: `ignored` or `processed`, what the driver itself inherited, read from
  its own PEB before anything changes it (`unknown (...)` if it cannot be read).
  `tests/native/m02/run-windows-local.ps1` copies it into `host.txt` as `ctrl-c-inherited=...`.
- `heimdall_ctrl_c` in each row's `observed`: heimdall's disposition as created, read from its PEB
  right after `CreateProcessW` (`processed` expected).

The G02 harness (`tests/native/windows-g02`) leaves `ChildCtrlCProcessed` at its default (`false`),
so its children inherit as before.

The Windows-native cases of `tests/e2e/run_m02.rs` (`a27_windows_*`,
`windows_holder_is_launcher_and_forced_launcher_kill_is_reported`) are ordinary `cargo test`
targets: they compile for `x86_64-pc-windows-gnu` (`tools/validation/clippy-windows.sh`) and run on
the Windows host with the rest of the suite.

Not covered (owner inputs, m02-plan §7 B5, P-W07): an interactive conhost window or Windows Terminal
with an operator pressing Ctrl-C or resizing the window.

## Running (Windows host)

1. Build the debug `heimdall.exe` for `x86_64-pc-windows-gnu` (the test configuration exists only in
   debug builds) and argvdump: in `tests/native/windows-g02/argvdump`,
   `GOOS=windows GOARCH=amd64 go build -o argvdump.exe`.
2. Copy both and this directory plus `tests/native/windows-g02` into a scratch directory on the host,
   non-elevated.
3. `powershell -NoProfile -ExecutionPolicy Bypass -File Invoke-WindowsLaunch.ps1 -Heimdall
   <heimdall.exe> -ArgvDump <argvdump.exe> [-Out <report.json>]`.

Exit 0 when every gating row passes, 1 otherwise, 2 for a harness error. The driver uses its own
scratch `HEIMDALL_HOME` under `%TEMP%` with the env-gated test configuration (`HEIMDALL_TEST_ADAPTER=prepare`,
`HEIMDALL_TEST_TIME_SYNC=synchronized`, profile `ops`), stops the runtime it started with
`heimdall service stop` on that home, and removes exactly that scratch directory. It reads no SSH,
Git or agent material of the account and opens no `\\.\pipe\openssh-ssh-agent`.
