"""Self-test of the replay driver (tests/contracts/replay_journey.py): a dump that holds any
forbidden item is refused, and a clean one is not; the ssh guard on the journey's `PATH` logs
and exits 1. Standard library only; runs nothing but the driver's functions and the guard's
own scripts, in a temporary directory."""

import importlib.util
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("replay_journey", os.path.join(HERE, "replay_journey.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)

ROOT = "/tmp/u0-replay/run-x-main"
CLEAN = f"INSERT INTO t VALUES('{ROOT}/hh/run/a.sock','binding_00000000000000000000000000000001');"


class RefuseTest(unittest.TestCase):
    def test_a_clean_dump_passes(self):
        DRIVER.refuse(CLEAN, ROOT, user="fixtureuser")

    def test_each_forbidden_item_is_refused(self):
        canary = "HEIMDALL_" + "CANARY_x"
        armor = "-----BEGIN OPENSSH PRIVATE " + "KEY-----"
        # Built at run time, so this source holds no home-path or canary-shaped literal.
        home_mac = "/" + "Users/someone/.ssh/id"
        home_linux = "/" + "home/someone/.ssh/id"
        for bad in (home_mac, home_linux, canary, armor,
                    "owner fixtureuser wrote this"):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(SystemExit):
                    DRIVER.refuse(CLEAN + bad, ROOT, user="fixtureuser")

    def test_a_path_inside_the_scratch_root_is_not_a_home_path(self):
        DRIVER.refuse(f"{ROOT}/home/x", ROOT, user="fixtureuser")


class GuardTest(unittest.TestCase):
    def test_every_guarded_program_logs_and_exits_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "guard.log")
            guard = DRIVER.write_guard(os.path.join(tmp, "guard"), log)
            env = {"PATH": guard + ":/usr/bin:/bin"}
            for name in DRIVER.GUARDED:
                with self.subTest(name=name):
                    p = subprocess.run([name, "-V"], env=env, stdin=subprocess.DEVNULL,
                                       capture_output=True, check=False)
                    self.assertEqual(p.returncode, 1)
            with open(log, encoding="ascii") as f:
                self.assertEqual(f.read().splitlines(), [f"{n} -V" for n in DRIVER.GUARDED])


if __name__ == "__main__":
    unittest.main()
