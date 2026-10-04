// Musl probe: dlopen OpenTUI's native core from a sidecar path and call one no-argument symbol.
import { dlopen, FFIType } from "bun:ffi";
const lib = process.argv[2];
try {
  const l = dlopen(lib, { getArenaAllocatedBytes: { args: [], returns: FFIType.u64 } });
  console.log("FFI_OK arena_bytes=" + String(l.symbols.getArenaAllocatedBytes()) + " arch=" + process.arch + " platform=" + process.platform);
} catch (e) {
  console.log("FFI_FAIL " + String((e as Error).message).slice(0, 200));
  process.exit(1);
}
