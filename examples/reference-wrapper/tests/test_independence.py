"""Keep the wrapper and journey driver independent of the runtime layout."""

import ast
from pathlib import Path
import re
import unittest


EXAMPLE = Path(__file__).resolve().parents[1]
# Explicit for Python 3.9, which has no sys.stdlib_module_names.
STANDARD = frozenset({
    "__future__", "copy", "ctypes", "functools", "importlib", "json", "math", "os", "pathlib", "runpy",
    "socket", "stat", "struct", "sys", "time", "traceback", "typing",
})
STATE_ACCESS = re.compile(
    r"instance\.json|\.sqlite\b|\.db\b|(?:^|[/\\])state(?:[/\\]|$)|"
    r"HEIMDALL_HOME|XDG_STATE_HOME|sqlite3|\b(?:sqlalchemy|database)\b",
    re.IGNORECASE,
)


class Independence(unittest.TestCase):
    def test_sources_use_only_stdlib_and_the_adjacent_wrapper_modules(self):
        for name in ("reference_wrapper.py", "reference_wrapper_windows.py", "journey.py"):
            with self.subTest(source=name):
                tree = ast.parse((EXAMPLE / name).read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        self.assertTrue(all(a.name.split(".")[0] in STANDARD for a in node.names))
                    elif isinstance(node, ast.ImportFrom):
                        self.assertEqual(node.level, 0)
                        self.assertIn(node.module.split(".")[0], STANDARD)
                    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                        self.assertIsNone(STATE_ACCESS.search(node.value))
                    elif isinstance(node, ast.Call):
                        loader = ast.unparse(node.func)
                        if loader == "runpy.run_path":
                            self.assertEqual(name, "journey.py")
                            self.assertEqual(
                                ast.unparse(node.args[0]),
                                "str(Path(__file__).with_name('reference_wrapper.py'))",
                            )
                        elif loader == "importlib.util.spec_from_file_location":
                            self.assertEqual(name, "reference_wrapper.py")
                            self.assertEqual([ast.unparse(arg) for arg in node.args], ["name", "beside"])
                        else:
                            self.assertNotIn(loader, {"__import__", "importlib.import_module"})
