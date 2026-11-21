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


@unittest.skipUnless(SMOKE_BIN, "set HEIMDALL_WRAPPER_SMOKE_BIN to the prebuilt debug binary")
@unittest.skipUnless(sys.platform in ("darwin", "linux"), "requires Darwin or Linux Unix sockets")
class RealBinarySmoke(unittest.TestCase):
    def test_control_endpoint(self):
        binary = Path(SMOKE_BIN)
        self.assertTrue(binary.is_absolute() and binary.is_file(), "supply an absolute debug binary path")
        root = Path(tempfile.mkdtemp(prefix="hm-u5a-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, root)
        root = root.resolve()
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "HEIMDALL_TEST_TIME_SYNC": "synchronized",
        }
        for key, name in zip(HOME_KEYS, ("home", "heimdall", "ssh")):
            directory = root / name
            directory.mkdir(mode=0o700)
            env[key] = str(directory)
        (Path(env["HEIMDALL_TEST_SSH_HOME"]) / "etc-ssh").mkdir(mode=0o700)

        homes = [Path(env[key]).resolve(strict=True) for key in HOME_KEYS]
        self.assertEqual(len(set(homes)), len(HOME_KEYS))
        self.assertTrue(all(path.is_dir() and root in path.parents for path in homes))
        self.assertFalse(list((homes[-1] / "etc-ssh").iterdir()))
        self.assertNotIn("SSH_AUTH_SOCK", env)

        runtime = subprocess.Popen(
            [binary, "service", "run"], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        status_codes = []
        try:
            status = self.wait_for_status(binary, env, runtime, status_codes)
            self.assertEqual(status["data"]["pid"], runtime.pid)
            expected = status["data"]["environment_id"]
            endpoint = Path(env["HEIMDALL_HOME"]) / "run" / "control.sock"
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
