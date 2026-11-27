from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

# Isolated mode removes the example directory from the default import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reference_wrapper import Client, code_defaults  # noqa: E402


SMOKE_BIN = os.environ.get("HEIMDALL_WRAPPER_SMOKE_BIN")
HOME_KEYS = ("HOME", "HEIMDALL_HOME", "HEIMDALL_TEST_SSH_HOME")
WINDOWS = sys.platform == "win32"


@unittest.skipUnless(SMOKE_BIN, "set HEIMDALL_WRAPPER_SMOKE_BIN to the prebuilt debug binary")
@unittest.skipUnless(sys.platform in ("darwin", "linux", "win32"), "requires Darwin, Linux or Windows")
class RealBinarySmoke(unittest.TestCase):
    def test_control_endpoint(self):
        binary = Path(SMOKE_BIN)
        self.assertTrue(binary.is_absolute() and binary.is_file(), "supply an absolute debug binary path")
        root = Path(tempfile.mkdtemp(prefix="hm-u5a-", dir=None if WINDOWS else "/tmp"))
        self.addCleanup(shutil.rmtree, root)
        root = root.resolve()
        mgmt_store = root / "mgmt-store"
        iroh_store = root / "iroh-key-store"
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "HEIMDALL_TEST_TIME_SYNC": "synchronized",
            "HEIMDALL_TEST_SECRET_STORE": "scratch",
            "HEIMDALL_TEST_MGMT_STORE": f"fixture-file:{mgmt_store}",
            "HEIMDALL_TEST_IROH_KEY_STORE": str(iroh_store),
        }
        for key, name in zip(HOME_KEYS, ("home", "heimdall", "ssh")):
            directory = root / name
            directory.mkdir(mode=0o700)
            env[key] = str(directory)
        (Path(env["HEIMDALL_TEST_SSH_HOME"]) / "etc-ssh").mkdir(mode=0o700)
        inside = list(HOME_KEYS)
        if WINDOWS:
            # The platform minimum, with the profile, ProgramData and temporary files in the root.
            system = Path(os.environ["SystemRoot"])
            (root / "tmp").mkdir()
            env.update({
                "SystemRoot": str(system),
                "PATH": os.pathsep.join(map(str, (system / "System32" / "OpenSSH", system / "System32", system))),
                "USERPROFILE": env["HOME"], "ProgramData": env["HOME"],
                "TEMP": str(root / "tmp"), "TMP": str(root / "tmp"),
            })
            inside += ["USERPROFILE", "ProgramData", "TEMP", "TMP"]

        homes = [Path(env[key]).resolve(strict=True) for key in HOME_KEYS]
        self.assertEqual(len(set(homes)), len(HOME_KEYS))
        self.assertTrue(all(root in Path(env[key]).resolve(strict=True).parents for key in inside))
        for store in (mgmt_store, iroh_store):
            self.assertEqual(store.resolve().parent, root)
            self.assertFalse(os.path.lexists(store))
        self.assertTrue(all(path.is_dir() for path in homes))
        self.assertFalse(list((homes[-1] / "etc-ssh").iterdir()))
        self.assertNotIn("SSH_AUTH_SOCK", env)

        runtime = subprocess.Popen(
            [binary, "service", "run"], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        status_codes = []
        try:
            status = self.wait_for_status(binary, env, runtime, status_codes)
            # Discovery (ADR-0013 §8, D12): every field from the CLI's verified connection. The
            # endpoint is the one it connected to (on Windows the pipe name carries an
            # unpredictable token only the runtime can report); this test never reads
            # instance.json.
            data = status["data"]
            self.assertEqual(data["pid"], runtime.pid)
            self.assertIsInstance(data["protocol"], int)
            expected = data["environment_id"]
            endpoint = data["control_endpoint"]
            self.assertIsInstance(endpoint, str)
            if WINDOWS:
                self.assertRegex(endpoint, r"^\\\\\.\\pipe\\heimdall-[A-Za-z0-9-]+-control$")
            else:
                self.assertEqual(Path(endpoint), Path(env["HEIMDALL_HOME"]) / "run" / "control.sock")
            with Client(endpoint, expected, required=("events/1",), timeout=2) as client:
                self.assertIn("events/1", client.capabilities)
                capabilities = client.request("inspect", subject="capabilities")
                self.assertTrue(code_defaults(capabilities).success)
                self.assertIn("events/1", capabilities["data"]["capabilities"])
                destinations = client.request("inspect", subject="destinations")
                self.assertTrue(code_defaults(destinations).success)
                self.assertIsInstance(destinations["data"]["items"], list)
                head = client.subscribe()
                self.assertEqual(head["snapshot"]["cursor"], head["cursor"])
                # The typed whole snapshot (ADR-0013 §5.5): no filter, so the local owner gets
                # both sections; no boundary_seq.
                data = head["snapshot"]["data"]
                self.assertEqual(data["environment_id"], expected)
                self.assertIsInstance(data["authority_generation"], int)
                self.assertEqual((data["operations"], data["pending_decisions"]), ([], []))
                self.assertNotIn("operation", data)
                self.assertNotIn("boundary_seq", data)
                self.assertNotIn("backlog", head)
                self.assertNotIn("resync_reason", head)
                self.assertTrue(code_defaults(client.unsubscribe()).success)
                # A backlog start from that cursor counts the frames that follow exactly
                # (ADR-0013 §5.3); a cursor it cannot resume restarts from a snapshot that
                # says why.
                resumed = client.subscribe(cursor=head["cursor"])
                self.assertNotIn("snapshot", resumed)
                self.assertIsInstance(resumed["backlog"], int)
                self.assertTrue(code_defaults(client.unsubscribe()).success)
                restarted = client.subscribe(cursor="AAAA")
                self.assertEqual(restarted["resync_reason"], "cursor_invalid")
                self.assertEqual(restarted["snapshot"]["cursor"], restarted["cursor"])
                self.assertTrue(code_defaults(client.unsubscribe()).success)
        finally:
            stop_code = None
            try:
                stop = subprocess.run(
                    [binary, "service", "stop"], env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                )
                stop_code = stop.returncode
            finally:
                if runtime.poll() is None:
                    runtime.terminate()
                try:
                    runtime.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    runtime.kill()
                    runtime.wait(timeout=3)
                print(f"smoke child exit codes: status={status_codes}, stop={stop_code}, run={runtime.returncode}")
        self.assertEqual(stop_code, 0, "service stop failed")
        self.assertEqual(runtime.returncode, 0, "runtime did not exit cleanly")
        for store in (mgmt_store, iroh_store):
            self.assertFalse(os.path.lexists(store), store.name)

    def wait_for_status(self, binary, env, runtime, status_codes):
        deadline = time.monotonic() + 10
        while (remaining := deadline - time.monotonic()) > 0:
            self.assertIsNone(runtime.poll(), "scratch runtime exited before it was ready")
            try:
                status = subprocess.run(
                    [binary, "--json", "service", "status"], env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=min(1, remaining),
                )
            except subprocess.TimeoutExpired:
                status_codes.append("timed_out")
                continue
            status_codes.append(status.returncode)
            if status.returncode == 0:
                return json.loads(status.stdout)
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        self.fail("scratch runtime did not report ready within 10 seconds")


if __name__ == "__main__":
    unittest.main()
