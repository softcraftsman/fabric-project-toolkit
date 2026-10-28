"""Synthetic-only tests for the conservative privacy policy core."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("privacy_guard", ROOT / "tools" / "privacy_guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
SYNTHETIC = "SYNTHETIC_SENTINEL_NOT_BUSINESS_DATA"


class PrivacyGuardTests(unittest.TestCase):
    def setUp(self):
        # Scratch stays under the workspace; it is never an approved plugin file.
        self.directory = tempfile.TemporaryDirectory(prefix="privacy-test-", dir=ROOT)
        self.addCleanup(self.cleanup_project)
        self.root = Path(self.directory.name)
        self.policy = guard.empty_policy()
        self.file = self.root / "sample.py"
        self.file.write_text("answer = 42\n", encoding="utf-8")
        # Production rejects the entire installed plugin package. These synthetic
        # projects live beneath it solely to obey workspace-only file operations.
        self.plugin = mock.patch.object(guard, "PLUGIN_ROOT", ROOT / "tools")
        self.plugin.start()
        self.addCleanup(self.plugin.stop)
        (self.root / ".copilot-privacy").mkdir()
        self.save()

    def cleanup_project(self):
        # Windows filesystem observers can briefly hold newly created directories.
        for attempt in range(20):
            try:
                self.directory.cleanup()
                return
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.1)

    def save(self):
        (self.root / guard.POLICY_PATH).write_text(json.dumps(self.policy), encoding="utf-8")

    def classify(self, relative="sample.py"):
        path = self.root.joinpath(*relative.split("\\"))
        self.policy["files"].append({
            "path": relative, "category": "source",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
        self.save()

    def decision(self, name, args=None, **extra):
        payload = {"toolName": name, "toolArgs": {} if args is None else args, "cwd": str(self.root)}
        payload.update(extra)
        return guard.hook(json.dumps(payload))

    def denied(self, name, args=None, **extra):
        result = self.decision(name, args, **extra)
        self.assertEqual(result.get("permissionDecision"), "deny")
        return result

    def cli(self, *args, input=None, cwd=None):
        return subprocess.run(
            [sys.executable, "-I", str(ROOT / "tools" / "privacy_guard.py"), *args],
            cwd=cwd or self.root, input=input, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15,
        )

    def test_empty_policy_and_fixed_check_metadata(self):
        self.assertEqual(guard.check(self.root), {
            "status": "ok", "reason": "POLICY_CHECK_ONLY", "files": 0, "tasks": 0,
        })
        self.denied("view", {"path": str(self.file)})
        self.assertEqual(self.decision("ask_user", {"question": "Review synthetic source?"}), {})
        self.denied("ask_user", {"question": "Review?", "permissionDecision": "allow"})

    def test_unknown_capabilities_and_prefix_spoofing_denied(self):
        for name in (
            "mcp.read", "web_fetch", "web_search", "session_store_sql", "get_diagnostics",
            "task", "skill", "sql", "browser", "glob", "bash", "apply_patch",
            "functions.apply_patch", "functions.mcp.read", "functions.functions.view",
            "future_tool", "get_file_contents",
        ):
            with self.subTest(name=name):
                self.denied(name, {"path": str(self.file)})
        self.denied("task", {
            "agent_type": "fabric-project-toolkit:solution-architect",
            "prompt": "Review synthetic source",
        })
        self.denied("functions.task", {
            "agent_type": "fabric-project-toolkit:quality-engineer",
            "prompt": "Run synthetic tests",
        })

    def test_malformed_payloads_bom_encoding_and_no_input_leaks(self):
        for raw in (
            b"", b"\xff", b"[]", b"null", b'{"a":1,"a":2}',
            b'{"x":NaN}', ("[" * 1500).encode(),
            json.dumps({"toolName": SYNTHETIC}).encode(),
            b"x" * (guard.MAX_INPUT_BYTES + 1),
            '{"toolName":"\\ud800"}',
        ):
            with self.subTest(raw_type=type(raw).__name__, length=len(raw)):
                decision = guard.hook(raw)
                self.assertEqual(decision["permissionDecision"], "deny")
                self.assertNotIn(SYNTHETIC, json.dumps(decision))
        payload = {"toolName": "ask_user", "toolArgs": {"question": "Review?"}, "cwd": str(self.root)}
        self.assertEqual(guard.hook(b"\xef\xbb\xbf" + json.dumps(payload).encode()), {})
        payload["unknown"] = SYNTHETIC
        self.assertEqual(guard.hook(json.dumps(payload))["permissionDecision"], "deny")

    def test_exact_hashed_reads_and_scoped_search(self):
        self.classify()
        for name in ("view", "functions.view"):
            self.assertEqual(self.decision(name, {"path": str(self.file)}), {})
        self.assertEqual(self.decision("view", json.dumps({"path": "sample.py"})), {})
        self.denied("view", '{"path":"sample.py","path":"sample.py"}')
        self.assertEqual(self.decision("view", {"path": "sample.py", "view_range": [1, -1]}), {})
        for name in ("rg", "grep", "functions.rg"):
            self.assertEqual(self.decision(name, {
                "pattern": "answer", "paths": ["sample.py"], "output_mode": "content",
                "-n": True, "-C": 1,
            }), {})
        for name in ("grep", "functions.grep"):
            self.assertEqual(self.decision(name, {"pattern": "answer", "path": "sample.py"}), {})
            self.denied(name, {"pattern": "answer", "path": "."})
            self.denied(name, {"pattern": "answer", "path": ["sample.py"]})
            self.denied(name, {"pattern": "answer", "path": "sample.py", "paths": "sample.py"})
            self.denied(name, {"pattern": "answer", "path": "sample.py", "glob": "*.py"})
        self.denied("rg", {"pattern": "answer", "path": "sample.py"})
        for args in (
            {"pattern": "answer"}, {"pattern": "answer", "paths": []},
            {"pattern": "answer", "paths": "."},
            {"pattern": "answer", "paths": [str(self.root)]},
            {"pattern": "answer", "paths": ["sample.py", "missing.py"]},
            {"pattern": "answer", "paths": "sample.py", "glob": "**"},
            {"pattern": "answer", "paths": "sample.py", "type": "py"},
            {"pattern": "answer", "paths": "sample.py", "extra_args": "--files"},
            {"pattern": "answer", "paths": "sample.py", "-C": True},
            {"pattern": "--pre=unreviewed", "paths": "sample.py"},
        ):
            self.denied("rg", args)
        self.denied("view", {"path": str(self.root)})
        self.denied("view", {"path": "sample.py", "view_range": [True, -1]})
        self.denied("view", {"path": "sample.py", "forceReadLargeFiles": "true"})

    def test_reviewed_edits_only_then_digest_drift_blocks(self):
        self.classify()
        self.assertEqual(self.decision("edit", {"path": "sample.py", "old_str": "42", "new_str": "43"}), {})
        self.assertEqual(self.decision("create", {"path": "sample.py", "file_text": "answer = 43\n"}), {})
        self.denied("create", {"path": "new.py", "file_text": "answer = 43\n"})
        self.denied("edit", {"path": "sample.py", "old_str": "42", "new_str": "43", "move": "new.py"})
        self.file.write_text("answer = 43\n", encoding="utf-8")
        for name, args in (
            ("view", {"path": "sample.py"}),
            ("rg", {"pattern": "answer", "paths": "sample.py"}),
            ("edit", {"path": "sample.py", "old_str": "43", "new_str": "44"}),
        ):
            self.denied(name, args)
        with self.assertRaisesRegex(guard.PolicyError, "STALE_DIGEST"):
            guard.check(self.root)

    def test_schema_validation_unknown_fields_types_and_duplicate_paths(self):
        entry = {"path": "sample.py", "category": "source", "sha256": "a" * 64}
        invalid = (
            {"version": True, "files": [], "tasks": {}},
            {"version": 1, "files": {}, "tasks": {}},
            {"version": 1, "files": [], "tasks": []},
            {**guard.empty_policy(), "extra": SYNTHETIC},
            {**guard.empty_policy(), "files": [{**entry, "category": []}]},
            {**guard.empty_policy(), "files": [{**entry, "sha256": "A" * 64}]},
            {**guard.empty_policy(), "files": [entry, {**entry, "path": "SAMPLE.PY"}]},
            {**guard.empty_policy(), "tasks": {"Bad": {"argv": ["python"], "reviewed": True}}},
            {**guard.empty_policy(), "tasks": {"test": {"argv": [], "reviewed": True}}},
            {**guard.empty_policy(), "tasks": {"test": {"argv": ["python"], "reviewed": 1}}},
            {**guard.empty_policy(), "tasks": {"test": {"argv": ["python", ""], "reviewed": True}}},
            {**guard.empty_policy(), "tasks": {"test": {"argv": ["python", "\0"], "reviewed": True}}},
            {**guard.empty_policy(), "tasks": {"test": {"argv": ["python"], "reviewed": True, "shell": True}}},
        )
        for policy in invalid:
            with self.subTest(policy_keys=list(policy)):
                with self.assertRaises(guard.PolicyError):
                    guard.validate_policy(copy.deepcopy(policy))
        (self.root / guard.POLICY_PATH).write_bytes(b'{"version":1,"files":[],"tasks":{},"tasks":{}}')
        self.denied("ask_user", {"question": "Review?"})

    def test_paths_reject_traversal_aliases_controls_and_directories(self):
        for path in (
            "..\\sample.py", ".\\sample.py", "sample.py.", "sample.py ",
            "sample.py:stream", "sample.py\\", "a\\\\b", "a/b",
            "C:\\sample.py", "\\\\server\\share\\sample.py", "SAMPL~1.PY",
            "NUL", "a\\CON.txt", "*.py", "-file.py", "e\u0301.py",
            ".copilot-privacy\\policy.json", ".github\\hooks\\config.json",
            ".vscode\\settings.json", "AGENTS.md", "hooks.json", "plugin.json",
            "tools\\privacy_guard.py", "skills\\example.md",
        ):
            with self.subTest(path_kind="invalid"):
                with self.assertRaises((guard.PolicyError, OSError)):
                    guard.classified_path(self.root, path)
        with self.assertRaises(guard.PolicyError):
            guard.classified_path(self.root, ".copilot-privacy")
        self.classify()
        self.denied("view", {"path": str(self.root / ".." / self.root.name / "sample.py")})
        self.denied("view", {"path": str(ROOT / "PROJECT-GOALS.md")})
        with mock.patch.object(guard, "PLUGIN_ROOT", ROOT):
            with self.assertRaisesRegex(guard.PolicyError, "CONTROL_PATH"):
                guard.classified_path(self.root, "sample.py")

    def test_symlink_and_policy_link_denied_when_supported(self):
        link = self.root / "linked.py"
        try:
            link.symlink_to(self.file)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable")
        with self.assertRaisesRegex(guard.PolicyError, "LINK_PATH"):
            guard.classified_path(self.root, "linked.py")
        policy_path = self.root / guard.POLICY_PATH
        backup = self.root / "policy-copy.json"
        backup.write_bytes(policy_path.read_bytes())
        policy_path.unlink()
        policy_path.symlink_to(backup)
        self.denied("ask_user", {"question": "Review?"})

    def test_windows_reparse_attribute_denied_without_following(self):
        actual = Path.lstat

        def synthetic_lstat(path):
            info = actual(path)
            if path == self.file:
                return mock.Mock(st_mode=info.st_mode, st_file_attributes=0x400)
            return info

        with mock.patch.object(Path, "lstat", synthetic_lstat):
            with self.assertRaisesRegex(guard.PolicyError, "LINK_PATH"):
                guard.classified_path(self.root, "sample.py")

    def test_no_parent_policy_discovery_and_invalid_root(self):
        child = self.root / "child"
        child.mkdir()
        self.denied("ask_user", {"question": "Review?"}, cwd=str(child))
        self.denied("ask_user", {"question": "Review?"}, cwd=".")

    def test_human_attestation_required_atomic_update_and_no_contents(self):
        original = (self.root / guard.POLICY_PATH).read_bytes()
        with self.assertRaisesRegex(guard.PolicyError, "HUMAN_REVIEW_REQUIRED"):
            guard.approve(self.root, "sample.py", "source")
        self.assertEqual((self.root / guard.POLICY_PATH).read_bytes(), original)
        result = guard.approve(self.root, "sample.py", "source", reviewed=True)
        self.assertEqual(result, {"status": "approved", "reason": "HUMAN_ATTESTATION_NOT_SAFETY_PROOF"})
        self.assertEqual(self.decision("view", {"path": "sample.py"}), {})
        self.file.write_text("answer = 43\n", encoding="utf-8")
        guard.approve(self.root, "sample.py", "synthetic", reviewed=True)
        policy = guard.load_policy(self.root)
        self.assertEqual(len(policy["files"]), 1)
        self.assertEqual(policy["files"][0]["category"], "synthetic")
        self.assertFalse(list((self.root / ".copilot-privacy").glob("update-*")))
        rejected = self.cli("approve", "--project", str(self.root), "--path", SYNTHETIC, "--category", "source")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn(SYNTHETIC.encode(), rejected.stdout + rejected.stderr)
        self.assertEqual(rejected.stderr, b"")

    def test_root_and_subdirectory_approval_expand_to_reviewed_files(self):
        source = self.root / "src"
        nested = source / "nested"
        nested.mkdir(parents=True)
        first = source / "first.py"
        second = nested / "second.py"
        first.write_text("first = 1\n", encoding="utf-8")
        second.write_text("second = 2\n", encoding="utf-8")
        settings = self.root / ".vscode"
        settings.mkdir()
        (settings / "settings.json").write_text("{}", encoding="utf-8")

        result = guard.approve(self.root, ".", "source", reviewed=True)

        self.assertEqual(result["files"], 3)
        self.assertGreaterEqual(result["excluded_control_paths"], 2)
        policy = guard.load_policy(self.root)
        self.assertEqual(
            {"sample.py", "src\\first.py", "src\\nested\\second.py"},
            {entry["path"] for entry in policy["files"]},
        )
        self.assertEqual(
            {}, self.decision("view", {"path": "src\\nested\\second.py"}),
        )

        first.unlink()
        (source / "third.py").write_text("third = 3\n", encoding="utf-8")
        guard.approve(self.root, "src", "synthetic", reviewed=True)
        policy = guard.load_policy(self.root)
        self.assertEqual(
            {"sample.py", "src\\nested\\second.py", "src\\third.py"},
            {entry["path"] for entry in policy["files"]},
        )
        self.assertEqual(
            {"synthetic"},
            {entry["category"] for entry in policy["files"] if entry["path"].startswith("src\\")},
        )

    def test_directory_approval_rejects_links_without_changing_policy(self):
        source = self.root / "src"
        source.mkdir()
        link = source / "linked.py"
        try:
            link.symlink_to(self.file)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable")
        original = (self.root / guard.POLICY_PATH).read_bytes()
        with self.assertRaisesRegex(guard.PolicyError, "LINK_PATH"):
            guard.approve(self.root, "src", "source", reviewed=True)
        self.assertEqual(original, (self.root / guard.POLICY_PATH).read_bytes())

    def test_isolated_installation_cli_approval_and_recheck(self):
        installation = self.root / "installation" / "tools"
        installation.mkdir(parents=True)
        engine = installation / "privacy_guard.py"
        shutil.copyfile(ROOT / "tools" / "privacy_guard.py", engine)
        consumer = self.root / "consumer"
        (consumer / ".copilot-privacy").mkdir(parents=True)
        (consumer / ".copilot-privacy" / "policy.json").write_text(
            json.dumps(guard.empty_policy()), encoding="utf-8",
        )
        (consumer / "synthetic.py").write_text("answer = 42\n", encoding="utf-8")
        command = [sys.executable, "-I", str(engine)]
        approval = subprocess.run(
            [*command, "approve", "--project", str(consumer), "--path", "synthetic.py",
             "--category", "synthetic", "--reviewed"],
            cwd=consumer, capture_output=True, timeout=15,
        )
        self.assertEqual(approval.returncode, 0)
        self.assertEqual(approval.stderr, b"")
        self.assertEqual(json.loads(approval.stdout)["reason"], "HUMAN_ATTESTATION_NOT_SAFETY_PROOF")
        source = consumer / "src"
        source.mkdir()
        (source / "module.py").write_text("value = 43\n", encoding="utf-8")
        approval = subprocess.run(
            [*command, "approve", "--project", str(consumer), "--path", ".",
             "--category", "source", "--reviewed"],
            cwd=consumer, capture_output=True, timeout=15,
        )
        self.assertEqual(approval.returncode, 0)
        self.assertEqual(approval.stderr, b"")
        self.assertEqual(json.loads(approval.stdout)["files"], 2)
        result = subprocess.run(
            [*command, "check", "--project", str(consumer)], cwd=consumer,
            capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["files"], 2)
        (consumer / "synthetic.py").write_text("answer = 43\n", encoding="utf-8")
        result = subprocess.run(
            [*command, "check", "--project", str(consumer)], cwd=consumer,
            capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {"status": "error", "reason": "STALE_DIGEST"})
        self.assertNotIn(b"synthetic.py", result.stdout + result.stderr)

    def add_task(self, code="print('synthetic task')"):
        self.policy["tasks"]["test"] = {
            "argv": [sys.executable, "-I", "-c", code], "reviewed": True,
        }
        self.save()

    def test_exact_wrapper_and_injection_denials(self):
        self.add_task()
        self.classify()
        command = guard.runner_command("test")
        self.assertEqual(self.decision("powershell", {"command": command}), {})
        self.assertEqual(self.decision("functions.powershell", {
            "command": command, "description": "Run synthetic tests", "mode": "sync",
            "detach": False, "initial_wait": 120,
        }), {})
        for altered in (
            command + "; echo synthetic", command + "\n", " " + command,
            command + " --project elsewhere", command.replace("-I", ""),
            command.replace("run --task", "check --task"), "python -I other.py run --task test",
        ):
            self.denied("powershell", {"command": altered})
        for extras in ({"mode": "async"}, {"detach": True}, {"shellId": "session"}, {"extra": True}):
            self.denied("powershell", {"command": command, **extras})
        for task in ("test;echo", "test\n", "../test", "TEST", "x" * 42):
            with self.assertRaises(guard.PolicyError):
                guard.runner_command(task)
        self.file.write_text("answer = 43\n", encoding="utf-8")
        self.denied("powershell", {"command": command})

    def test_runner_command_single_quote_escaping(self):
        with mock.patch.object(guard, "__file__", str(self.root / "literal'path" / "privacy_guard.py")):
            command = guard.runner_command("test")
        self.assertIn("literal''path", command)

    def test_subprocess_runner_suppresses_success_failure_and_spawn_errors(self):
        for code, expected, exit_code in (
            (f"print('{SYNTHETIC}'); import sys; print('{SYNTHETIC}', file=sys.stderr)", "success", 0),
            (f"raise RuntimeError('{SYNTHETIC}')", "failure", 1),
            (f"import sys; print('{SYNTHETIC}'); sys.exit(7)", "failure", 7),
        ):
            self.add_task(code)
            result = self.cli("run", "--task", "test")
            self.assertEqual(result.stderr, b"")
            self.assertNotIn(SYNTHETIC.encode(), result.stdout)
            self.assertEqual(json.loads(result.stdout), {"task": "test", "status": expected, "exit_code": exit_code})
        self.policy["tasks"]["test"]["argv"] = [SYNTHETIC]
        self.save()
        result = self.cli("run", "--task", "test")
        self.assertEqual(json.loads(result.stdout), {"task": "test", "status": "failure", "exit_code": None})
        self.assertNotIn(SYNTHETIC.encode(), result.stdout + result.stderr)

    def test_runner_bounds_output_and_denies_drift_before_launch(self):
        self.add_task("import sys; sys.stdout.write('x' * 2000000); sys.stdout.flush()")
        result = self.cli("run", "--task", "test")
        self.assertEqual(json.loads(result.stdout)["status"], "failure")
        self.assertLess(len(result.stdout), 200)
        self.classify()
        self.file.write_text("answer = 43\n", encoding="utf-8")
        with mock.patch.object(guard.Path, "cwd", return_value=self.root):
            with mock.patch.object(guard.subprocess, "Popen") as start:
                with self.assertRaisesRegex(guard.PolicyError, "STALE_DIGEST"):
                    guard.run_task("test")
                start.assert_not_called()

    def test_runner_timeout_returns_metadata_without_child_output(self):
        self.add_task(f"import time; print('{SYNTHETIC}', flush=True); time.sleep(2)")
        with mock.patch.object(guard.Path, "cwd", return_value=self.root):
            with mock.patch.object(guard, "TASK_TIMEOUT_SECONDS", 0.05):
                result = guard.run_task("test")
        self.assertEqual(result["task"], "test")
        self.assertEqual(result["status"], "failure")
        self.assertEqual(set(result), {"task", "status", "exit_code"})
        self.assertNotIn(SYNTHETIC, json.dumps(result))

    def test_hook_cli_returns_json_only_and_sanitizes_errors(self):
        malformed = self.cli("hook", input=(SYNTHETIC + "{").encode())
        self.assertEqual(malformed.returncode, 0)
        self.assertEqual(malformed.stderr, b"")
        self.assertEqual(json.loads(malformed.stdout)["permissionDecision"], "deny")
        self.assertNotIn(SYNTHETIC.encode(), malformed.stdout)
        unknown = self.cli(SYNTHETIC)
        self.assertEqual(json.loads(unknown.stdout), {"status": "error", "reason": "INVALID_CLI"})
        self.assertEqual(unknown.stderr, b"")


if __name__ == "__main__":
    unittest.main()
