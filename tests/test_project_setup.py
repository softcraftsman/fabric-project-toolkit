import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("project_setup", ROOT / "tools" / "project_setup.py")
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


def remove_tree(path):
    for attempt in range(50):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except PermissionError:
            if attempt == 49:
                raise
            time.sleep(0.05)


class ProjectWorkspace:
    def setUp(self):
        self.scratch = ROOT / (".test-project-setup-" + uuid.uuid4().hex)
        self.scratch.mkdir()
        self.addCleanup(remove_tree, self.scratch)
        self.project = self.scratch / "curated project"
        self.project.mkdir()

    def invoke(self, function, *args, **kwargs):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            status = function(*args, **kwargs)
        output = stream.getvalue()
        self.assertNotIn(str(self.project), output)
        self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", output)
        self.assertNotIn("protected", output.lower())
        result = json.loads(output)
        self.assertEqual("UNVERIFIED", result["cli_runtime"])
        self.assertEqual("ADVISORY_NOT_TOOL_ENFORCED", result["vscode"])
        return status, result

    def initialize(self):
        status, _ = self.invoke(setup.initialize, self.project)
        self.assertEqual(0, status)
        return self.project / setup.POLICY_DIRECTORY

    def make_plugin(self, script=None):
        plugin = self.scratch / "installed plugin cache"
        (plugin / "hooks").mkdir(parents=True)
        (plugin / "tools").mkdir()
        for relative in (
            Path("plugin.json"), Path("hooks") / "hooks.json",
            Path("hooks") / "Invoke-PrivacyGuard.ps1",
        ):
            shutil.copyfile(ROOT / relative, plugin / relative)
        engine = plugin / "tools" / "privacy_guard.py"
        if script is None:
            shutil.copyfile(ROOT / "tools" / "privacy_guard.py", engine)
        else:
            engine.write_text(script, encoding="utf-8")
        return plugin


class ProjectSetupTests(ProjectWorkspace, unittest.TestCase):
    def test_manifest_retains_all_fabric_agent_profiles_alongside_hook(self):
        manifest = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
        agents = ROOT / manifest["agents"]
        self.assertEqual(
            {
                "solution-architect", "semantic-model-engineer", "quality-engineer",
                "notebook-enablement-author", "independent-reviewer", "fabric-operator",
                "delivery-lead", "data-pipeline-engineer", "application-ai-engineer",
            },
            {path.name.removesuffix(".agent.md") for path in agents.glob("*.agent.md")},
        )
        self.assertEqual("hooks/hooks.json", manifest["hooks"])

    def test_init_serializes_policy_profile_and_preserves_user_files(self):
        existing = {
            Path(".github") / "copilot-instructions.md": "SYNTHETIC_PRIVATE_SENTINEL",
            Path(".github") / "copilot" / "settings.json": '{"existing":true}',
            Path(".vscode") / "settings.json": '{"editor.tabSize":2}',
        }
        for relative, content in existing.items():
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        target = self.initialize()
        self.assertEqual(
            {"version": 1, "files": [], "tasks": {}},
            json.loads((target / "policy.json").read_text(encoding="utf-8")),
        )
        settings = json.loads((target / setup.PROFILE_NAME).read_text(encoding="utf-8"))
        self.assertIs(False, settings["chat.agent.enabled"])
        self.assertEqual("none", settings["chat.mcp.access"])
        for key in (
            "chat.mcp.discovery.enabled", "chat.useAgentSkills", "chat.plugins.enabled",
            "chat.tools.terminal.enableAutoApprove", "chat.tools.global.autoApprove",
        ):
            self.assertIs(False, settings[key])
        self.assertEqual({}, settings["chat.tools.terminal.autoApprove"])
        guidance = (target / "guidance.txt").read_text(encoding="utf-8")
        self.assertIn("NOT TOOL-ENFORCED", guidance)
        self.assertIn("curated code-only workspace", guidance)
        self.assertIn("inline/context ingestion", guidance)
        for relative, content in existing.items():
            self.assertEqual(content, (self.project / relative).read_text(encoding="utf-8"))
        self.assertFalse((target / "privacy_guard.py").exists())

    def test_every_predictable_collision_leaves_no_partial_writes(self):
        target = self.project / setup.POLICY_DIRECTORY
        for name in ("policy.json", setup.PROFILE_NAME, "guidance.txt", "settings.json"):
            with self.subTest(name=name):
                target.mkdir()
                existing = target / name
                existing.write_text("SYNTHETIC_PRIVATE_SENTINEL", encoding="utf-8")
                status, result = self.invoke(setup.initialize, self.project)
                self.assertEqual(1, status)
                self.assertEqual(["INIT_COLLISION"], result["codes"])
                self.assertEqual([name], [path.name for path in target.iterdir()])
                self.assertEqual("SYNTHETIC_PRIVATE_SENTINEL", existing.read_text(encoding="utf-8"))
                remove_tree(target)
        target.write_text("existing", encoding="utf-8")
        status, _ = self.invoke(setup.initialize, self.project)
        self.assertEqual(1, status)
        self.assertEqual("existing", target.read_text(encoding="utf-8"))

    def test_repeated_init_does_not_replace_reviewed_policy(self):
        target = self.initialize()
        before = {path.name: path.read_bytes() for path in target.iterdir()}
        status, _ = self.invoke(setup.initialize, self.project)
        self.assertEqual(1, status)
        self.assertEqual(before, {path.name: path.read_bytes() for path in target.iterdir()})

    def test_relative_or_missing_root_is_rejected_without_writes(self):
        for project in (Path("relative project"), self.scratch / "missing"):
            with self.subTest(project=project):
                status, result = self.invoke(setup.initialize, project)
                self.assertEqual(1, status)
                self.assertEqual(["PROJECT_INVALID"], result["codes"])

    def test_write_failure_rolls_back_only_generated_content(self):
        with mock.patch.object(Path, "open", side_effect=OSError("SYNTHETIC_PRIVATE_SENTINEL")):
            status, result = self.invoke(setup.initialize, self.project)
        self.assertEqual(1, status)
        self.assertEqual(["INIT_WRITE_FAILED"], result["codes"])
        self.assertFalse((self.project / setup.POLICY_DIRECTORY).exists())

    def test_preflight_missing_and_bad_policy_are_safe(self):
        plugin = self.make_plugin("raise SystemExit(1)\n")
        status, result = self.invoke(setup.preflight, self.project, plugin)
        self.assertEqual(1, status)
        self.assertIn("POLICY_MISSING_OR_INVALID", result["codes"])
        target = self.initialize()
        (target / "policy.json").write_text("SYNTHETIC_PRIVATE_SENTINEL", encoding="utf-8")
        status, result = self.invoke(setup.preflight, self.project, plugin)
        self.assertEqual(1, status)
        self.assertIn("POLICY_INVALID_OR_DRIFT", result["codes"])

    def test_preflight_checks_engine_in_isolated_process_and_discards_output(self):
        self.initialize()
        plugin = self.make_plugin("raise SystemExit(0)\n")
        with mock.patch.object(
            setup.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0),
        ) as run:
            status, result = self.invoke(setup.preflight, self.project, plugin)
        command = run.call_args.args[0]
        self.assertEqual([sys.executable, "-I", str(plugin / "tools" / "privacy_guard.py")], command[:3])
        self.assertEqual(["check", "--project", str(self.project)], command[3:])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stdout"])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stderr"])
        self.assertEqual(0 if os.name == "nt" else 1, status)
        self.assertEqual("UNVERIFIED", result["client_version"])

    def test_engine_timeout_fails_without_exposing_exception(self):
        self.initialize()
        plugin = self.make_plugin("raise SystemExit(0)\n")
        with mock.patch.object(
            setup.subprocess, "run",
            side_effect=subprocess.TimeoutExpired("SYNTHETIC_PRIVATE_SENTINEL", 15),
        ):
            status, result = self.invoke(setup.preflight, self.project, plugin)
        self.assertEqual(1, status)
        self.assertIn("POLICY_CHECK_UNAVAILABLE", result["codes"])

    def test_preflight_detects_hook_and_profile_drift(self):
        target = self.initialize()
        plugin = self.make_plugin("raise SystemExit(0)\n")
        (plugin / "hooks" / "hooks.json").write_text('{"version":1,"hooks":{}}', encoding="utf-8")
        (target / setup.PROFILE_NAME).write_text("{}", encoding="utf-8")
        status, result = self.invoke(setup.preflight, self.project, plugin)
        self.assertEqual(1, status)
        self.assertIn("PLUGIN_WIRING_INVALID", result["codes"])
        self.assertIn("GENERATED_CONFIG_MISSING_OR_DRIFT", result["codes"])

    def test_local_override_content_is_never_opened(self):
        local = self.project / ".github" / "copilot" / "settings.local.json"
        local.parent.mkdir(parents=True)
        local.write_text("SYNTHETIC_PRIVATE_SENTINEL", encoding="utf-8")
        with mock.patch.object(setup, "load_json", side_effect=AssertionError("must not read local overrides")):
            codes, count = setup.inspect_repository(self.project)
        self.assertEqual(["LOCAL_OVERRIDE_REVIEW_REQUIRED"], codes)
        self.assertEqual(1, count)

    def test_conflicting_repo_settings_and_jsonc_require_review(self):
        cases = (
            (Path(".github") / "copilot" / "settings.json", '{"disableAllHooks":true}', "CLI_HOOKS_DISABLED"),
            (Path(".claude") / "settings.json", '{"enabledPlugins":{"SYNTHETIC_PRIVATE_SENTINEL":false}}', "CLI_SETTINGS_REVIEW_REQUIRED"),
            (Path(".vscode") / "settings.json", '{"chat.agent.enabled":true}', "VSCODE_OVERRIDE_CONFLICT"),
            (Path(".vscode") / "settings.json", '{/* SYNTHETIC_PRIVATE_SENTINEL */}', "REPO_SETTINGS_REVIEW_REQUIRED"),
        )
        for relative, content, expected in cases:
            with self.subTest(relative=relative, expected=expected):
                path = self.project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                codes, _ = setup.inspect_repository(self.project)
                self.assertIn(expected, codes)
                self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", json.dumps(codes))
                path.unlink()

    def test_preflight_real_engine_and_classification_drift(self):
        if not (ROOT / "tools" / "privacy_guard.py").is_file():
            self.skipTest("engine supplied by parallel implementation")
        self.initialize()
        plugin = self.make_plugin()
        source = self.project.parent / "external-synthetic.py"
        source.write_text("value = 1\n", encoding="utf-8")
        approved = subprocess.run(
            [sys.executable, "-I", str(plugin / "tools" / "privacy_guard.py"), "approve",
             "--project", str(self.project), "--path", str(source),
             "--category", "synthetic", "--reviewed"],
            capture_output=True, timeout=15, check=False,
        )
        self.assertEqual(0, approved.returncode)
        status, result = self.invoke(setup.preflight, self.project, plugin)
        self.assertEqual(0 if os.name == "nt" else 1, status)
        if os.name == "nt":
            self.assertEqual(["STATIC_CONFIGURATION_OK"], result["codes"])
        source.write_text("value = 2\n", encoding="utf-8")
        status, result = self.invoke(setup.preflight, self.project, plugin)
        self.assertEqual(1, status)
        self.assertIn("POLICY_INVALID_OR_DRIFT", result["codes"])


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"), "native Windows protocol only")
class WindowsHookTests(ProjectWorkspace, unittest.TestCase):
    def invoke_wrapper(self, plugin, payload, environment=None):
        hook = json.loads((plugin / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]["preToolUse"][0]
        environment = os.environ.copy() if environment is None else environment.copy()
        environment["COPILOT_PLUGIN_ROOT"] = str(plugin)
        result = subprocess.run(
            [shutil.which(hook["exec"]), *hook["args"]],
            input=payload, cwd=self.project, encoding="utf-8",
            capture_output=True, timeout=25, env=environment, check=False,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stderr)
        self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", result.stdout)
        self.assertEqual(1, len(result.stdout.splitlines()))
        return json.loads(result.stdout)

    def test_cache_path_with_spaces_preserves_exact_native_payload_and_isolation(self):
        plugin = self.make_plugin(
            "import json, sys\n"
            "payload = json.loads(sys.stdin.buffer.read().decode('utf-8-sig'))\n"
            "assert sys.flags.isolated == 1\n"
            "assert payload['toolName'] == 'view'\n"
            "assert payload['toolArgs']['path'] == 'synthetic-é.py'\n"
            "assert payload['cwd'].endswith('curated project')\n"
            "print('{}')\n"
        )
        payload = json.dumps({
            "cwd": str(self.project), "toolName": "view",
            "toolArgs": {"path": "synthetic-é.py"},
        }, ensure_ascii=False)
        self.assertEqual({}, self.invoke_wrapper(plugin, payload))

    def test_engine_failures_and_raw_reasons_are_not_disclosed(self):
        plugin = self.make_plugin("raise SystemExit(1)\n")
        scripts = (
            "import sys; print('SYNTHETIC_PRIVATE_SENTINEL'); sys.exit(1)\n",
            "print('not json SYNTHETIC_PRIVATE_SENTINEL')\n",
            "print('[{}]')\n",
            "print('{}'); print('{}')\n",
            "print('{\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"SYNTHETIC_PRIVATE_SENTINEL\"}')\n",
        )
        for script in scripts:
            with self.subTest(script_kind=scripts.index(script)):
                (plugin / "tools" / "privacy_guard.py").write_text(
                    "import sys; sys.stdin.buffer.read()\n" + script, encoding="utf-8",
                )
                result = self.invoke_wrapper(plugin, '{"toolArgs":"SYNTHETIC_PRIVATE_SENTINEL"}')
                self.assertEqual("deny", result["permissionDecision"])
        (plugin / "tools" / "privacy_guard.py").unlink()
        self.assertEqual("deny", self.invoke_wrapper(plugin, "{}")["permissionDecision"])
        (plugin / "hooks" / "Invoke-PrivacyGuard.ps1").unlink()
        self.assertEqual("deny", self.invoke_wrapper(plugin, "{}")["permissionDecision"])

    def test_missing_python_and_internal_timeout_deny(self):
        plugin = self.make_plugin("import time; time.sleep(20)\n")
        wrapper = plugin / "hooks" / "Invoke-PrivacyGuard.ps1"
        wrapper.write_text(
            wrapper.read_text(encoding="utf-8").replace("WaitForExit(15000)", "WaitForExit(100)"),
            encoding="utf-8",
        )
        self.assertEqual("deny", self.invoke_wrapper(plugin, "{}")["permissionDecision"])
        environment = os.environ.copy()
        environment["PATH"] = str(Path(shutil.which("powershell.exe")).parent)
        self.assertEqual("deny", self.invoke_wrapper(plugin, "{}", environment)["permissionDecision"])

    def test_real_engine_allows_reviewed_read_and_blocks_unknown_tool(self):
        if not (ROOT / "tools" / "privacy_guard.py").is_file():
            self.skipTest("engine supplied by parallel implementation")
        self.initialize()
        plugin = self.make_plugin()
        (self.project / "synthetic.py").write_text("value = 1\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-I", str(plugin / "tools" / "privacy_guard.py"), "approve",
             "--project", str(self.project), "--path", "synthetic.py",
             "--category", "synthetic", "--reviewed"],
            capture_output=True, timeout=15, check=False,
        )
        self.assertEqual(0, result.returncode)
        payload = {"cwd": str(self.project), "toolName": "view", "toolArgs": {"path": "synthetic.py"}}
        self.assertEqual({}, self.invoke_wrapper(plugin, json.dumps(payload)))
        payload["toolName"] = "unknown"
        self.assertEqual("deny", self.invoke_wrapper(plugin, json.dumps(payload))["permissionDecision"])


if __name__ == "__main__":
    unittest.main()
