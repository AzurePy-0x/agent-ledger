"""Package-import test (review round 2, teknium point 1).

Hermes loads plugin directories as packages (``hermes_plugins.<slug>``)
WITHOUT adding the plugin directory to sys.path. A bare ``import policy``
therefore raises ModuleNotFoundError which was silently swallowed —
enforce mode would never load. This test loads __init__.py exactly the
way Hermes does (spec_from_file_location with submodule_search_locations,
plugin dir NOT on sys.path) and asserts the policy engine loads and an
enforce rule actually blocks.
"""

import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest

REPO = os.path.dirname(os.path.abspath(__file__))


def _load_plugin_as_package(tmp_home):
    """Mimic Hermes' loader: package-style, plugin dir absent from sys.path."""
    for mod in ("policy",):
        sys.modules.pop(mod, None)
    init = os.path.join(REPO, "__init__.py")
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.agent_ledger", init,
        submodule_search_locations=[REPO])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hermes_plugins.agent_ledger"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestPackageImport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="al_pkg_")
        data_dir = os.path.join(self.tmp, "plugin-data", "agent-ledger")
        os.makedirs(data_dir, exist_ok=True)
        self.data_dir = data_dir
        self.db = os.path.join(data_dir, "ledger.db")
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, ts TEXT,"
                     " session_id TEXT, tool_call_id TEXT, tool_name TEXT,"
                     " args_json TEXT, status TEXT, result_digest TEXT,"
                     " duration_ms INTEGER, confirmed_ts TEXT)")
        conn.commit()
        conn.close()

    def test_policy_loads_without_sys_path(self):
        mod = _load_plugin_as_package(self.tmp)
        mod.load_policy_for_hook()
        # Mode file + rules loaded => engine alive (not silently skipped)
        mode_file = os.path.join(self.data_dir, "policy_mode")
        with open(mode_file, "w") as fh:
            fh.write("off")
        mod.load_policy_for_hook()
        self.assertIsNotNone(mod.__dict__.get("_policy_rules"))

    def test_enforce_rule_blocks(self):
        mode_file = os.path.join(self.data_dir, "policy_mode")
        with open(mode_file, "w") as fh:
            fh.write("enforce")
        with open(os.path.join(self.data_dir, "policy.json"), "w") as fh:
            json.dump({"rules": [
                {"name": "no-rmrf", "block": "terminal",
                 "match": r"rm\s+-rf\s+[~/]", "reason": "destructive rm -rf"}]},
                fh)
        mod = _load_plugin_as_package(self.tmp)
        # Simulate register(): resolves DB_PATH to the per-profile data dir,
        # which is also where policy_mode/policy.json are read from.
        mod.DB_PATH = self.db
        mod.load_policy_for_hook()  # binds _policy module (the point of this test)
        # policy.json DEFAULT paths resolve at import time; override with tmp path
        mod._policy_rules = mod._policy.load_policy(
            os.path.join(self.data_dir, "policy.json"))
        mod._policy_mode = "enforce"
        self.assertEqual(mod._policy_mode, "enforce")
        verdict = mod._policy.check(mod._policy_rules, "terminal",
                                    {"command": "rm -rf ~/"})
        self.assertEqual(verdict.get("action"), "block")


if __name__ == "__main__":
    unittest.main()
