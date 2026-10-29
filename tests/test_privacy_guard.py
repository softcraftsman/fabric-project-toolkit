"""Synthetic-only tests for the conservative privacy policy core."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
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
        self.assertEqual(self.decision("view", {"path": str(self.file)}), {})
        self.assertEqual(self.decision("ask_user", {"question": "Review synthetic source?"}), {})
        self.denied("ask_user", {"question": "Review?", "permissionDecision": "allow"})

    def test_unknown_capabilities_and_prefix_spoofing_denied(self):
        for name in (
            "mcp.read", "web_search", "get_diagnostics",
            "sql", "browser", "bash", "apply_patch",
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

    def test_curated_skills_load_without_granting_upstream_osmos_or_query_access(self):
        for skill in guard.CURATED_SKILLS:
            for name in (skill, "fabric-project-toolkit:" + skill):
                self.assertEqual({}, self.decision("skill", {"skill": name}))
        for name in (
            "project-osmos", "fabric-skills:project-osmos",
            "fabric-project-toolkit:project-osmos",
            "fabric-project-toolkit:privacy-fabric-unreviewed",
        ):
            self.denied("skill", {"skill": name})
        self.denied("powershell", {
            "command": "python -I 'tools\\osmos_boundary.py' run",
        })
        self.denied("osmos-run", {"task_id": "synthetic"})
        self.denied("fabric-sqlendpoint-execute_query", {"query": "SELECT 1"})
        self.denied("edit", {
            "path": str(self.root / "osmos_boundary.py"),
            "old_str": "False", "new_str": "True",
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

    def test_project_reads_and_explicit_file_searches(self):
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
            self.assertEqual(self.decision(name, {"pattern": "answer", "path": "."}), {})
            self.denied(name, {"pattern": "answer", "path": ["sample.py"]})
            self.denied(name, {"pattern": "answer", "path": "sample.py", "paths": "sample.py"})
            self.assertEqual(self.decision(name, {"pattern": "answer", "path": "sample.py", "glob": "*.py"}), {})
        self.denied("rg", {"pattern": "answer", "path": "sample.py"})
        for args in (
            {"pattern": "answer", "paths": []},
            {"pattern": "answer", "paths": ["sample.py", "missing.py"]},
            {"pattern": "answer", "paths": "sample.py", "extra_args": "--files"},
            {"pattern": "answer", "paths": "sample.py", "-C": True},
            {"pattern": "--pre=unreviewed", "paths": "sample.py"},
        ):
            self.denied("rg", args)
        self.assertEqual(self.decision("view", {"path": str(self.root)}), {})
        self.denied("view", {"path": "sample.py", "view_range": [True, -1]})
        self.denied("view", {"path": "sample.py", "forceReadLargeFiles": "true"})

    def test_project_files_need_no_inventory_or_digest_even_after_edits(self):
        self.classify()
        self.assertEqual(self.decision("edit", {"path": "sample.py", "old_str": "42", "new_str": "43"}), {})
        self.assertEqual(self.decision("create", {"path": "sample.py", "file_text": "answer = 43\n"}), {})
        self.assertEqual(self.decision("create", {"path": "new.py", "file_text": "answer = 43\n"}), {})
        self.denied("edit", {"path": "sample.py", "old_str": "42", "new_str": "43", "move": "new.py"})
        self.file.write_text("answer = 43\n", encoding="utf-8")
        for name, args in (
            ("view", {"path": "sample.py"}),
            ("rg", {"pattern": "answer", "paths": "sample.py"}),
            ("edit", {"path": "sample.py", "old_str": "43", "new_str": "44"}),
        ):
            self.assertEqual(self.decision(name, args), {})
        guard.check(self.root)
        nested = self.root / "src"
        nested.mkdir()
        (nested / "new.py").write_text("answer = 44\n", encoding="utf-8")
        with mock.patch.object(guard, "digest", side_effect=AssertionError("Project file hashed")):
            self.assertEqual(self.decision("view", {"path": "src\\new.py"}), {})
            self.assertEqual(self.decision("rg", {"pattern": "answer", "paths": "src\\new.py"}), {})
            guard.check(self.root)
        self.denied("create", {"path": ".copilot-privacy\\new.json", "file_text": "{}"})
        self.denied("create", {"path": "missing\\new.py", "file_text": ""})
        self.denied("create", {"path": "..\\new.py", "file_text": ""})

    def test_repository_discovery_supports_native_patterns_and_protects_writes(self):
        docs = self.root / "docs" / "designs"
        docs.mkdir(parents=True)
        (docs / "Silver.md").write_text("synthetic silver tasks\n", encoding="utf-8")
        for name, arguments in (
            ("glob", {"pattern": "docs/**/*Silver*"}),
            ("functions.glob", {"pattern": "**/*.md", "paths": str(self.root / "docs")}),
            ("rg", {"pattern": "silver"}),
            ("rg", {"pattern": "silver", "paths": "docs", "glob": "*.md"}),
            ("grep", {"pattern": "silver", "path": str(self.root), "type": "md"}),
            ("view", {"path": str(self.root / "docs")}),
            ("view", {"path": "docs/designs/Silver.md"}),
            ("view", {"path": str(self.root / guard.POLICY_PATH)}),
        ):
            with self.subTest(name=name, arguments=arguments):
                self.assertEqual(self.decision(name, arguments), {})
        self.denied("edit", {
            "path": str(self.root / guard.POLICY_PATH), "old_str": "1", "new_str": "2",
        })
        for arguments in (
            {"pattern": "../*"}, {"pattern": "docs/../../*"},
            {"pattern": "**", "paths": str(self.root.parent)},
            {"pattern": str(self.root.parent / "*")},
            {"pattern": "{docs,../outside}/**"},
            {"pattern": "**", "paths": []},
        ):
            self.denied("glob", arguments)
        self.denied("rg", {"pattern": "silver", "paths": ".."})
        self.denied("rg", {"pattern": "silver", "glob": "../*"})

    def test_directory_discovery_rejects_reparse_points_hardlinks_and_scan_limits(self):
        actual = Path.lstat

        def reparse(path):
            info = actual(path)
            if path == self.file:
                return mock.Mock(st_mode=info.st_mode, st_file_attributes=0x400)
            return info

        for name, args in (
            ("glob", {"pattern": "**/*"}),
            ("rg", {"pattern": "synthetic", "paths": "."}),
            ("view", {"path": str(self.root)}),
        ):
            with mock.patch.object(Path, "lstat", reparse):
                self.denied(name, args)
        alias = self.root / "hardlink.py"
        os.link(self.file, alias)
        self.denied("glob", {"pattern": "*.py"})
        alias.unlink()
        with mock.patch.object(guard, "MAX_SEARCH_ENTRIES", 1):
            self.denied("glob", {"pattern": "**/*"})

    def history_arguments(self, query, **changes):
        return {
            "query": query, "description": "Read project history", "source": "local",
            **changes,
        }

    def test_history_templates_only_return_sessions_for_exact_current_project(self):
        cwd = str(self.root).replace("'", "''")
        sessions = (
            f"SELECT id, summary, updated_at FROM sessions WHERE cwd = '{cwd}' "
            "ORDER BY updated_at DESC LIMIT 20"
        )
        turns = (
            "SELECT t.session_id, t.user_message, t.assistant_response FROM turns AS t "
            f"JOIN sessions AS s ON t.session_id = s.id WHERE s.cwd = '{cwd}' "
            "ORDER BY t.timestamp DESC LIMIT 50"
        )
        with sqlite3.connect(":memory:") as db:
            db.executescript(
                "CREATE TABLE sessions (id TEXT, summary TEXT, cwd TEXT, updated_at TEXT);"
                "CREATE TABLE turns (session_id TEXT, user_message TEXT, assistant_response TEXT, timestamp TEXT);"
            )
            db.executemany("INSERT INTO sessions VALUES (?, ?, ?, ?)", [
                ("current", "project", str(self.root), "2026-10-29"),
                ("other", "other project", str(self.root) + "-other", "2026-10-29"),
            ])
            db.executemany("INSERT INTO turns VALUES (?, ?, ?, ?)", [
                ("current", "project prompt", "project reply", "2026-10-29"),
                ("other", "other prompt", "other reply", "2026-10-29"),
            ])
            for name in ("session_store_sql", "functions.session_store_sql"):
                for query in (sessions, turns, sessions + ";"):
                    self.assertEqual(self.decision(name, self.history_arguments(query)), {})
                    self.assertEqual(len(db.execute(query).fetchall()), 1)
                    self.assertEqual(db.execute(query).fetchone()[0], "current")
            db.executemany("INSERT INTO turns VALUES (?, ?, ?, ?)", [
                ("current", "silver work", "project reply", "2026-10-29")
                for _ in range(120)
            ] + [
                ("other", "silver work", "other reply", "2026-10-29")
                for _ in range(130)
            ])
            flexible = (
                "SELECT h.* FROM turns h JOIN sessions s ON h.session_id=s.id "
                f"WHERE s.cwd='{cwd}' AND (h.user_message LIKE '%silver%' "
                "OR h.assistant_response LIKE '%silver%') ORDER BY h.timestamp ASC"
            )
            self.assertEqual(self.decision("session_store_sql", self.history_arguments(flexible)), {})
            rows = db.execute(flexible).fetchall()
            self.assertEqual(len(rows), 120)
            self.assertEqual({row[0] for row in rows}, {"current"})
            aggregate = (
                "SELECT count(*) FROM turns h JOIN sessions s ON h.session_id=s.id "
                f"WHERE h.user_message LIKE '%silver%' AND s.cwd='{cwd}'"
            )
            self.assertEqual(self.decision("session_store_sql", self.history_arguments(aggregate)), {})
            self.assertEqual(db.execute(aggregate).fetchone()[0], 120)
        for table, order in (
            ("checkpoints", "created_at"), ("session_files", "first_seen_at"),
            ("session_refs", "created_at"),
        ):
            query = (
                f"SELECT t.session_id FROM {table} AS t JOIN sessions AS s "
                f"ON t.session_id=s.id WHERE s.cwd='{cwd}' ORDER BY t.{order} DESC LIMIT 10"
            )
            self.assertEqual(self.decision("session_store_sql", self.history_arguments(query)), {})

    def test_history_rejects_unscoped_cloud_cross_project_and_sql_escape_attempts(self):
        cwd = str(self.root).replace("'", "''")
        query = (
            f"SELECT id FROM sessions WHERE cwd='{cwd}' ORDER BY updated_at DESC LIMIT 10"
        )
        for unsafe in (
            "SELECT id FROM sessions ORDER BY updated_at DESC LIMIT 10",
            query.replace(cwd, cwd + "-other"),
            query.replace(f"cwd='{cwd}'", f"cwd='{cwd}' OR 1=1"),
            query + " UNION SELECT id FROM sessions",
            query + "; SELECT id FROM sessions",
            query.replace("SELECT id", "SELECT (SELECT summary FROM sessions)"),
            query.replace(f"'{cwd}'", "'x' /*"),
            "ATTACH DATABASE 'other' AS other",
            "SELECT load_extension('unsafe')",
            "DELETE FROM sessions",
            "SELECT t.user_message FROM turns AS t JOIN sessions AS s "
            f"ON t.session_id=s.id OR 1=1 WHERE s.cwd='{cwd}' "
            "ORDER BY t.timestamp DESC LIMIT 10",
            "SELECT t.user_message FROM turns AS t JOIN sessions AS s "
            f"ON tXsession_id=sXid WHERE s.cwd='{cwd}' "
            "ORDER BY t.timestamp DESC LIMIT 10",
        ):
            self.denied("session_store_sql", self.history_arguments(unsafe))
        self.denied("session_store_sql", self.history_arguments(query, source="cloud"))
        args = self.history_arguments(query)
        del args["source"]
        self.assertEqual(
            self.denied("session_store_sql", args)["permissionDecisionReason"],
            "HISTORY_SCOPE_REQUIRED",
        )

    def test_history_search_filters_aggregates_and_unlimited_project_rows(self):
        cwd = str(self.root).replace("'", "''")
        allowed = (
            f"SELECT * FROM sessions WHERE cwd='{cwd}'",
            f"SELECT id FROM sessions WHERE cwd='{cwd}' LIMIT 500",
            f"SELECT COUNT(*) FROM sessions WHERE summary LIKE '%silver%' AND cwd='{cwd}'",
            f"SELECT id, summary FROM sessions AS s WHERE s.cwd='{cwd}' "
            "AND (summary LIKE '%silver%' OR summary LIKE '%bronze%') "
            "AND updated_at >= datetime('now', '-7 days') ORDER BY created_at ASC",
            "SELECT h.session_id, h.user_message FROM turns h "
            f"INNER JOIN sessions s ON h.session_id=s.id WHERE s.cwd='{cwd}' "
            "AND h.user_message LIKE '%silver%' ORDER BY h.timestamp DESC LIMIT 200 OFFSET 10",
            "SELECT s.branch, COUNT(*) AS hits FROM turns AS t "
            f"JOIN sessions AS s ON t.session_id=s.id WHERE s.cwd='{cwd}' "
            "GROUP BY s.branch HAVING count(*) > 1 ORDER BY hits DESC",
        )
        for query in allowed:
            with self.subTest(query=query):
                self.assertEqual(self.decision("session_store_sql", self.history_arguments(query)), {})
        for query in (
            f"SELECT * FROM sessions WHERE cwd='{cwd}' AND 1=1 OR 1=1",
            f"SELECT * FROM sessions WHERE (cwd='{cwd}' OR 1=1)",
            f"SELECT readfile('other') FROM sessions WHERE cwd='{cwd}'",
            f"SELECT * FROM sessions WHERE cwd='{cwd}' UNION SELECT * FROM sessions",
            f"SELECT * FROM sessions WHERE cwd='{cwd}' ORDER BY (SELECT summary FROM sessions)",
            f"SELECT * FROM sessions WHERE cwd='{cwd}' COLLATE NOCASE",
            f"SELECT row_number() OVER () FROM sessions WHERE cwd='{cwd}'",
        ):
            self.denied("session_store_sql", self.history_arguments(query))

    def test_exact_git_status_and_read_only_inspection_are_allowed(self):
        for name in ("powershell", "functions.powershell"):
            for command in (
                "git --no-pager status --short",
                "git -c core.fsmonitor=false --no-pager status --short",
            ):
                self.assertEqual(self.decision(name, {"command": command}), {})
                self.denied(name, {"command": command + "; Get-Content secret"})
                self.denied(name, {"command": command, "mode": "async"})
        self.assertEqual(self.decision("powershell", {"command": "git --no-pager diff"}), {})

    def test_project_directory_wrapper_creates_nested_paths_without_external_or_control_access(self):
        relative = "src\\new module\\nested"
        command = guard.directory_command(relative)
        self.assertEqual(self.decision("powershell", {"command": command}), {})
        with mock.patch.object(guard.Path, "cwd", return_value=self.root):
            self.assertEqual(guard.make_directory(relative)["status"], "created")
        self.assertTrue((self.root / "src" / "new module" / "nested").is_dir())
        self.assertEqual(self.decision("create", {
            "path": relative + "\\example.py", "file_text": "answer = 42\n",
        }), {})
        for path in ("..\\outside", ".github\\hooks", "src\\agents\\nested", "AGENTS.md"):
            command = (
                "python -I '" + str(Path(guard.__file__).resolve()).replace("'", "''")
                + "' mkdir --path '" + path + "'"
            )
            self.denied("powershell", {"command": command})
        self.denied("powershell", {"command": guard.directory_command("valid") + "; echo bypass"})
        real_lstat = Path.lstat
        linked = self.root / "junction"
        linked.mkdir()

        def reparse(path, *args, **kwargs):
            if path == linked:
                return mock.Mock(
                    st_mode=stat.S_IFDIR, st_file_attributes=0x400,
                )
            return real_lstat(path, *args, **kwargs)

        with mock.patch.object(Path, "lstat", reparse):
            self.denied("powershell", {"command": guard.directory_command("junction\\new")})
        self.assertFalse((linked / "new").exists())

    def test_git_diff_and_log_allow_full_output_and_deny_execution_options(self):
        for command in (
            "git --no-pager diff",
            "git --no-pager diff --cached --no-ext-diff --no-textconv",
            "git --no-pager diff HEAD~2 HEAD -- src\\example.py",
            "git --no-pager diff -- 'src\\an example (synthetic).py'",
            "git --no-pager log --all --graph --oneline -n100",
            "git --no-pager log -p --full-history",
        ):
            self.assertEqual(self.decision("powershell", {"command": command}), {})
        for command in (
            "git --no-pager diff --output=outside",
            "git --no-pager diff --ext-diff",
            "git --no-pager log --format=%x00",
            "git --no-pager log; Get-Content secret",
            "git --no-pager diff $(Get-Content secret)",
            "git --no-pager diff -- ..\\outside",
            "git --no-pager diff -- (whoami)",
            "git --no-pager log -- @(whoami)",
            "git --no-pager diff -- @example",
            "git --no-pager diff -- # example",
            "git -C .. --no-pager log",
            "git --no-pager diff --no-index outside other",
        ):
            self.denied("powershell", {"command": command})

    @unittest.skipUnless(shutil.which("git") and shutil.which("pwsh"), "Git and PowerShell required")
    def test_git_inspection_returns_actual_synthetic_diff_and_log_patches(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

        def git(*args):
            return subprocess.run(
                ["git", *args], cwd=self.root, env=environment,
                capture_output=True, check=True, timeout=15,
            )

        git("init", "--quiet")
        git("add", "sample.py")
        git("-c", "user.name=Synthetic Fixture", "-c", "user.email=synthetic@example.invalid",
            "commit", "--quiet", "-m", "Synthetic fixture")
        self.file.write_text("answer = 43\n", encoding="utf-8")
        for command, expected in (
            ("git --no-pager diff --no-ext-diff --no-textconv", b"+answer = 43"),
            ("git --no-pager log -p --no-ext-diff --no-textconv", b"+answer = 42"),
        ):
            self.assertEqual(self.decision("powershell", {"command": command}), {})
            result = subprocess.run(
                ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                cwd=self.root, env=environment, capture_output=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn(expected, result.stdout)

    def test_microsoft_documentation_and_fabric_skill_loading_are_scoped(self):
        for url in (
            "https://learn.microsoft.com/en-us/fabric/data-engineering/overview",
            "https://code.visualstudio.com/docs/python/testing",
            "https://docs.microsoft.com/en-us/azure/",
        ):
            self.assertEqual(self.decision("web_fetch", {"url": url}), {})
        for url in (
            "https://example.com/docs", "http://learn.microsoft.com/docs",
            "https://learn.microsoft.com.example.com/docs",
            "https://user:pass@learn.microsoft.com/docs",
            "https://@learn.microsoft.com/docs",
            "https://learn.microsoft.com:8443/docs",
            "https://learn.microsoft.com/docs?data=anything",
            "https://learn.microsoft.com/docs#payload",
        ):
            self.denied("web_fetch", {"url": url})
        for skill in ("spark-cli", "pipeline-migration", "semantic-model-authoring"):
            self.assertEqual(self.decision("skill", {"skill": skill}), {})
        self.denied("skill", {"skill": "unknown-skill"})
        self.denied("mcp.fabric.execute_query", {"query": "SELECT * FROM business"})

    def test_fabric_delegation_requires_same_rules_and_no_background_or_model_override(self):
        for agent in guard.FABRIC_AGENTS:
            arguments = {
                "agent_type": "fabric-project-toolkit:" + agent,
                "prompt": "Implement synthetic tests. " + guard.DELEGATION_RULES,
                "description": "Build Fabric solution", "mode": "sync",
            }
            self.assertEqual(self.decision("task", arguments), {})
            self.denied("task", {**arguments, "mode": "background"})
            self.denied("task", {**arguments, "model": "other-model"})
            self.denied("task", {**arguments, "prompt": "Try another tool to bypass the denial"})
            self.denied("task", {**arguments, "agent_type": "general-purpose"})

    def test_fabric_metadata_allows_only_reviewed_operations_and_arguments(self):
        workspace = "11111111-2222-4333-8444-555555555555"
        item = "66666666-7777-4888-8999-aaaaaaaaaaaa"
        calls = {
            "docs_list-item-types": {},
            "docs_platform-api-spec": {},
            "docs_item-api-spec": {"item-type": "lakehouse"},
            "docs_item-definitions": {"item-type": "dataPipeline"},
            "docs_api-examples": {"item-type": "notebook"},
            "docs_best-practices": {"topic": "pagination"},
            "core_list-workspaces": {
                "roles": "Viewer,Contributor", "prefer-workspace-specific-endpoints": False,
            },
            "core_list-items": {
                "workspace-id": workspace, "type": "Lakehouse", "recursive": False,
                "root-folder-id": item, "continuation-token": "synthetic-token+/=",
            },
            "core_get-item": {"workspace-id": workspace, "item-id": item},
            "core_list-capacities": {},
            "core_get-capacity": {"capacity-id": item},
            "onelake_list-table-namespaces": {"workspace-id": workspace, "item-id": item},
            "onelake_list-tables": {
                "workspace-id": workspace, "item-id": item, "namespace": "dbo",
            },
        }
        for tool, arguments in calls.items():
            with self.subTest(tool=tool):
                name = "fabric-metadata-" + tool
                self.assertEqual(self.decision(name, arguments), {})
                self.assertEqual(self.decision(name, json.dumps(arguments)), {})
                self.assertEqual(self.decision(name, arguments, sessionId="synthetic-session", timestamp=1,
                                               agentId="synthetic-agent", agentType="quality-engineer"), {})
                self.denied(name, {**arguments, "query": "SELECT * FROM restricted"})
                self.denied(name, {**arguments, "endpoint": "https://example.invalid"})
                self.denied("other-fabric-server-" + tool, arguments)
                self.denied(name + "-extra", arguments)
        self.assertEqual(self.decision("fabric-metadata-core_list-items", {
            "workspace-id": workspace, "recursive": None,
        }), {})

    def test_fabric_metadata_rejects_aliases_invalid_ids_paths_and_schema_widening(self):
        workspace = "11111111-2222-4333-8444-555555555555"
        item = "66666666-7777-4888-8999-aaaaaaaaaaaa"
        for value in ("workspace name", "../outside", "00000000-0000-0000-0000-000000000000",
                      workspace + "/items", workspace.replace("-", ""), None, True, 1, {}):
            self.denied("fabric-metadata-core_get-item", {"workspace-id": value, "item-id": item})
        for arguments in (
            {"workspace": workspace, "item": item, "schema": "dbo"},
            {"workspace-id": workspace, "item-id": item},
            {"workspace-id": workspace, "item-id": item, "namespace": "../other"},
            {"workspace-id": workspace, "item-id": item, "namespace": "dbo?query=rows"},
            {"workspace-id": workspace, "item-id": item, "namespace": "dbo", "table": "example"},
            {"workspace-id": workspace, "item-id": item, "namespace": "dbo", "includeData": True},
        ):
            self.denied("fabric-metadata-onelake_list-tables", arguments)
        for arguments in ({"roles": "Owner"}, {"roles": "Viewer,"},
                          {"prefer-workspace-specific-endpoints": True},
                          {"prefer-workspace-specific-endpoints": 0},
                          {"continuation-token": "token\nheader"}, {"continuation-token": "x" * 8193}):
            self.denied("fabric-metadata-core_list-workspaces", arguments)
        self.denied("fabric-metadata-core_list-items", {"workspace-id": workspace, "recursive": "false"})
        self.denied("fabric-metadata-docs_item-api-spec", {"item-type": "..\\policy.json"})
        self.denied("fabric-metadata-docs_best-practices", {"topic": "https://example.invalid"})
        self.denied("fabric-metadata-docs_list-item-types", {"authentication": "override"})
        self.denied("fabric-metadata-docs_list-item-types", {}, cwd=str(self.root / "missing"))

    def test_fabric_metadata_denies_data_execution_definitions_permissions_and_mutations(self):
        for tool in (
            "core_create-item", "core_delete-item", "core_update-item", "core_create-workspace",
            "core_get-workspace", "core_search-catalog", "core_get-operation-result",
            "core_get-operation-state", "core_assign-workspace-to-capacity",
            "datafactory_list-pipelines", "datafactory_get-pipeline", "datafactory_run-pipeline",
            "datafactory_execute-query", "datafactory_list-dataflows",
            "onelake_get-table", "onelake_get-table-config", "onelake_get-table-namespace",
            "onelake_download-file", "onelake_list-files", "onelake_upload-file",
            "onelake_get-data-access-role", "onelake_list-data-access-roles",
            "onelake_create-or-update-data-access-role", "onelake_list-shortcuts",
            "onelake_get-settings", "onelake_list-items-dfs", "onelake_delete-directory",
            "ExecuteQuery", "ValueSearch", "GetSemanticModelSchema", "GetReportMetadata",
            "execute_sql", "execute_kql", "future_metadata_tool",
        ):
            with self.subTest(tool=tool):
                decision = self.denied("fabric-metadata-" + tool, {"payload": SYNTHETIC})
                self.assertNotIn(SYNTHETIC, json.dumps(decision))
        for name in (
            "FabricIQ-ExecuteQuery", "FabricIQ-GetSemanticModelSchema",
            "fabric-list_items", "fabric-metadata_list_items",
            "fabric-metadata", "mcp__fabric-metadata__core_list-workspaces",
            "functions.fabric-metadata-core_list-workspaces",
        ):
            self.denied(name, {})

    def test_synthetic_test_diagnostics_return_full_bounded_output_only_when_attested(self):
        self.add_task("raise AssertionError('synthetic assertion: expected 42, got 43')")
        self.policy["tasks"]["test"].update(output="diagnostics", synthetic_only=True)
        self.save()
        result = self.cli("run", "--task", "test")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "failure")
        self.assertIn("synthetic assertion: expected 42, got 43", payload["output"])
        self.assertIn("Traceback", payload["output"])
        self.policy["tasks"]["test"]["argv"] = [
            sys.executable, "-I", "-c", "print('synthetic test passed')",
        ]
        self.save()
        payload = json.loads(self.cli("run", "--task", "test").stdout)
        self.assertEqual(payload["status"], "success")
        self.assertIn("synthetic test passed", payload["output"])
        self.policy["tasks"]["test"]["synthetic_only"] = False
        self.save()
        rejected = self.cli("run", "--task", "test")
        self.assertEqual(json.loads(rejected.stdout)["reason"], "SYNTHETIC_ATTESTATION_REQUIRED")

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
            "mcp-config.json", ".mcp.json",
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
            with mock.patch.object(Path, "exists", return_value=False):
                self.denied("create", {"path": "sample.py", "file_text": ""})

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
        self.assertEqual(result, {"status": "trusted", "reason": "PROJECT_ROOT_TRUSTED"})
        self.assertEqual(self.decision("view", {"path": "sample.py"}), {})
        self.file.write_text("answer = 43\n", encoding="utf-8")
        guard.approve(self.root, "sample.py", "synthetic", reviewed=True)
        policy = guard.load_policy(self.root)
        self.assertEqual(policy["files"], [])
        self.assertFalse(list((self.root / ".copilot-privacy").glob("update-*")))
        rejected = self.cli("approve", "--project", str(self.root), "--path", SYNTHETIC, "--category", "source")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn(SYNTHETIC.encode(), rejected.stdout + rejected.stderr)
        self.assertEqual(rejected.stderr, b"")

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
        external = self.root / "synthetic.py"
        external.write_text("answer = 42\n", encoding="utf-8")
        command = [sys.executable, "-I", str(engine)]
        approval = subprocess.run(
            [*command, "approve", "--project", str(consumer), "--path", str(external),
             "--category", "synthetic", "--reviewed"],
            cwd=consumer, capture_output=True, timeout=15,
        )
        self.assertEqual(approval.returncode, 0)
        self.assertEqual(approval.stderr, b"")
        self.assertEqual(json.loads(approval.stdout)["reason"], "HUMAN_ATTESTATION_NOT_SAFETY_PROOF")
        result = subprocess.run(
            [*command, "check", "--project", str(consumer)], cwd=consumer,
            capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["files"], 1)
        external.write_text("answer = 43\n", encoding="utf-8")
        result = subprocess.run(
            [*command, "check", "--project", str(consumer)], cwd=consumer,
            capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {"status": "error", "reason": "STALE_DIGEST"})
        self.assertNotIn(b"synthetic.py", result.stdout + result.stderr)

    def test_external_files_require_review_and_reapproval_for_reads_searches_and_edits(self):
        project = self.root / "consumer"
        (project / ".copilot-privacy").mkdir(parents=True)
        (project / guard.POLICY_PATH).write_text(json.dumps(guard.empty_policy()), encoding="utf-8")
        args = (
            ("view", {"path": str(self.file)}),
            ("rg", {"pattern": "answer", "paths": str(self.file)}),
            ("edit", {"path": str(self.file), "old_str": "42", "new_str": "43"}),
            ("create", {"path": str(self.file), "file_text": "answer = 43\n"}),
        )
        for name, arguments in args:
            self.denied(name, arguments, cwd=str(project))
        guard.approve(project, str(self.file), "source", reviewed=True)
        for name, arguments in args:
            self.assertEqual(self.decision(name, arguments, cwd=str(project)), {})
        self.file.write_text("answer = 43\n", encoding="utf-8")
        for name, arguments in args:
            self.assertEqual(
                self.denied(name, arguments, cwd=str(project))["permissionDecisionReason"],
                "STALE_DIGEST",
            )
        guard.approve(project, str(self.file), "source", reviewed=True)
        self.assertEqual(self.decision("view", {"path": str(self.file)}, cwd=str(project)), {})
        self.denied("create", {"path": str(self.root / "missing.py"), "file_text": ""}, cwd=str(project))

    def test_external_controls_and_project_prefix_sibling_are_not_trusted(self):
        sibling = self.root / "consumer-sibling"
        sibling.mkdir()
        external = sibling / "sample.py"
        external.write_text("answer = 42\n", encoding="utf-8")
        project = self.root / "consumer"
        (project / ".copilot-privacy").mkdir(parents=True)
        (project / guard.POLICY_PATH).write_text(json.dumps(guard.empty_policy()), encoding="utf-8")
        self.denied("view", {"path": str(external)}, cwd=str(project))
        control = sibling / "AGENTS.md"
        control.write_text("Synthetic instructions\n", encoding="utf-8")
        with self.assertRaisesRegex(guard.PolicyError, "CONTROL_PATH"):
            guard.approve(project, str(control), "source", reviewed=True)

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
        self.assertEqual(self.decision("powershell", {"command": command}), {})

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
        project = self.root / "consumer"
        (project / ".copilot-privacy").mkdir(parents=True)
        external_policy = guard.empty_policy()
        external_policy["tasks"] = self.policy["tasks"]
        (project / guard.POLICY_PATH).write_text(json.dumps(external_policy), encoding="utf-8")
        guard.approve(project, str(self.file), "source", reviewed=True)
        self.file.write_text("answer = 43\n", encoding="utf-8")
        with mock.patch.object(guard.Path, "cwd", return_value=project):
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
