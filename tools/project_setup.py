"""Non-destructive project setup and static checks; never reports runtime protection."""

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


PLUGIN_ROOT = Path(__file__).resolve().parent.parent
POLICY_DIRECTORY = ".copilot-privacy"
PROFILE_NAME = "advisory-settings.json"
VSCODE_SETTINGS = {
    "chat.agent.enabled": False,
    "chat.mcp.access": "none",
    "chat.mcp.discovery.enabled": False,
    "chat.useAgentSkills": False,
    "chat.plugins.enabled": False,
    "chat.tools.terminal.enableAutoApprove": False,
    "chat.tools.terminal.autoApprove": {},
    "chat.tools.global.autoApprove": False,
}
HOOK_ARGUMENTS = [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    """try { $ErrorActionPreference = 'Stop'; & (Join-Path $env:COPILOT_PLUGIN_ROOT 'hooks\\Invoke-PrivacyGuard.ps1') } catch { [Console]::Out.WriteLine('{"permissionDecision":"deny","permissionDecisionReason":"CLI_GUARD_FAILURE"}'); exit 0 }""",
]
GUIDANCE = """VS Code: ADVISORY / NOT TOOL-ENFORCED
Create a new empty profile (Profiles: Create Profile), open its settings with
Preferences: Open Profile Settings (JSON), paste the contents of
advisory-settings.json, then select Use this Profile for Current Window. Keep the
new profile free of extensions and MCP servers. Verify the active profile and
effective settings after setup and after every client upgrade.
Use only a curated code-only workspace containing human-reviewed source and
synthetic data. Source can contain secrets or business values; review it first.
The profile does not enforce classification, disable inline/context ingestion,
or make mixed/sensitive workspaces safe. Empty extensions/MCP lists do not
override extensions applied to all profiles or workspace/enterprise settings.

CLI: native Windows preToolUse baseline only; fresh-session runtime UNVERIFIED.
Install the reusable plugin manually. Do not copy its engine into this project.
Run the installed plugin's tools\\project_setup.py preflight --project PATH
from a human terminal. Run tools\\privacy_guard.py approve only after human
content review, using --project PATH --path REL --category source|synthetic
--reviewed. Never approve business values or secrets. Changed files need review.
The policy root is the exact absolute hook cwd; no parent-directory lookup.
Hooks cannot control prompts, attachments, automatic context, or other clients.
CLI hook timeouts fail open. Static checks do not prove installation,
activation, hook dispatch, client compatibility, or personal/managed settings.
No setup command installs plugins, changes authentication, or edits personal
configuration, .github instructions/settings, or .vscode settings.
"""


def serialized(value):
    return json.dumps(value, indent=2, ensure_ascii=True) + "\n"


def generated_files():
    return {
        "policy.json": serialized({"version": 1, "files": [], "tasks": {}}),
        PROFILE_NAME: serialized(VSCODE_SETTINGS),
        "guidance.txt": GUIDANCE,
    }


def unsafe_path(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def validate_project(project):
    if not project.is_absolute() or not project.is_dir():
        return False
    return not any(unsafe_path(path) for path in (project, *project.parents))


def initialize(project):
    if not validate_project(project):
        return report(["PROJECT_INVALID"], 0)
    target = project / POLICY_DIRECTORY
    if target.exists() or target.is_symlink():
        return report(["INIT_COLLISION"], 1)
    # The entire generated directory is reserved. Existing files are never merged.
    contents = generated_files()
    created = []
    directory_created = False
    try:
        target.mkdir()
        directory_created = True
        for name, content in contents.items():
            path = target / name
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                created.append(path)
                stream.write(content)
    except OSError:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if directory_created and target.is_dir() and not any(target.iterdir()):
            target.rmdir()
        return report(["INIT_WRITE_FAILED"], 0)
    return report(["INIT_CREATED", "VSCODE_MANUAL_PROFILE_REQUIRED"], len(contents), failed=False)


def load_json(path):
    if unsafe_path(path) or not path.is_file() or path.stat().st_size > 1048576:
        raise ValueError("CONFIG_INVALID")
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_pairs)


def unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("CONFIG_INVALID")
        result[key] = value
    return result


def check_wiring(plugin_root):
    try:
        manifest = load_json(plugin_root / "plugin.json")
        hooks = load_json(plugin_root / "hooks" / "hooks.json")
        expected = {
            "version": 1,
            "hooks": {"preToolUse": [{
                "type": "command", "exec": "powershell.exe",
                "args": HOOK_ARGUMENTS, "timeoutSec": 30,
            }]},
        }
        if (
            manifest.get("name") != "fabric-project-toolkit"
            or manifest.get("hooks") != "hooks/hooks.json"
            or manifest.get("agents") != "agents/"
            or "$schema" in manifest
            or any(key in manifest for key in ("skills", "mcpServers", "lspServers", "extensions"))
            or hooks != expected
            or type(hooks.get("version")) is not int
        ):
            return False
        return all(
            path.is_file() and not unsafe_path(path)
            for path in (
                plugin_root / "hooks" / "Invoke-PrivacyGuard.ps1",
                plugin_root / "tools" / "privacy_guard.py",
            )
        )
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def inspect_repository(project):
    codes = []
    count = 0
    for relative in (
        (".github", "copilot", "settings.local.json"),
        (".claude", "settings.local.json"),
    ):
        path = project.joinpath(*relative)
        if path.exists() or path.is_symlink():
            count += 1
            codes.append("LOCAL_OVERRIDE_REVIEW_REQUIRED")
    for relative in (
        (".github", "copilot", "settings.json"),
        (".claude", "settings.json"),
        (".vscode", "settings.json"),
    ):
        path = project.joinpath(*relative)
        if not path.exists() and not path.is_symlink():
            continue
        count += 1
        try:
            if any(unsafe_path(parent) for parent in path.parents if parent != project and project in parent.parents):
                raise ValueError("CONFIG_INVALID")
            value = load_json(path)
            if not isinstance(value, dict):
                raise ValueError("CONFIG_INVALID")
            if relative[0] == ".vscode":
                if any(
                    key in value and (type(value[key]) is not type(expected) or value[key] != expected)
                    for key, expected in VSCODE_SETTINGS.items()
                ):
                    codes.append("VSCODE_OVERRIDE_CONFLICT")
            else:
                if value.get("disableAllHooks", False) is not False:
                    codes.append("CLI_HOOKS_DISABLED")
                if any(key in value for key in ("enabledPlugins", "hooks", "permissions", "sandbox")):
                    codes.append("CLI_SETTINGS_REVIEW_REQUIRED")
        except (OSError, ValueError, TypeError):
            # JSONC is deliberately not guessed: request manual review, never echo it.
            codes.append("REPO_SETTINGS_REVIEW_REQUIRED")
    for relative in (
        (".github", "hooks"), (".vscode", "mcp.json"),
        (".mcp.json",), (".github", "mcp.json"),
    ):
        path = project.joinpath(*relative)
        if path.exists() or path.is_symlink():
            count += 1
            codes.append("REPO_INTEGRATION_REVIEW_REQUIRED")
    if any(project.glob("*.code-workspace")):
        count += 1
        codes.append("WORKSPACE_REVIEW_REQUIRED")
    return codes, count


def preflight(project, plugin_root=None):
    plugin_root = PLUGIN_ROOT if plugin_root is None else plugin_root
    codes = []
    count = 0
    if not validate_project(project):
        return report(["PROJECT_INVALID"], 0)
    target = project / POLICY_DIRECTORY
    if target.exists() and unsafe_path(target):
        return report(["PROJECT_CONFIG_INVALID"], 0)
    policy = target / "policy.json"
    if not policy.is_file() or policy.is_symlink():
        codes.append("POLICY_MISSING_OR_INVALID")
    else:
        try:
            if unsafe_path(policy):
                raise ValueError("POLICY_INVALID")
            result = subprocess.run(
                [sys.executable, "-I", str(plugin_root / "tools" / "privacy_guard.py"),
                 "check", "--project", str(project)],
                cwd=str(plugin_root), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15, check=False,
            )
            if result.returncode != 0:
                codes.append("POLICY_INVALID_OR_DRIFT")
        except (OSError, ValueError, subprocess.SubprocessError):
            codes.append("POLICY_CHECK_UNAVAILABLE")
    if not check_wiring(plugin_root):
        codes.append("PLUGIN_WIRING_INVALID")
    for name in (PROFILE_NAME, "guidance.txt"):
        try:
            path = target / name
            if unsafe_path(path) or path.read_text(encoding="utf-8") != generated_files()[name]:
                raise ValueError("GENERATED_CONFIG_DRIFT")
        except (OSError, ValueError):
            codes.append("GENERATED_CONFIG_MISSING_OR_DRIFT")
    overrides, count = inspect_repository(project)
    codes.extend(overrides)
    if os.name != "nt":
        codes.append("PLATFORM_UNSUPPORTED")
    return report(codes or ["STATIC_CONFIGURATION_OK"], count, failed=bool(codes))


def report(codes, count, failed=True):
    print(json.dumps({
        "codes": sorted(set(codes)),
        "count": count,
        "cli_runtime": "UNVERIFIED",
        "client_version": "UNVERIFIED",
        "vscode": "ADVISORY_NOT_TOOL_ENFORCED",
    }, separators=(",", ":")))
    return 1 if failed else 0


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        report(["ARGUMENTS_INVALID"], 0)
        raise SystemExit(2)


def main(argv=None):
    parser = SafeParser(
        description="Create a classification policy and advisory VS Code profile; no installs or personal config changes."
    )
    commands = parser.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    for command, help_text in (
        ("init", "Create .copilot-privacy only; refuse any existing directory/content."),
        ("preflight", "Check static policy/wiring/overrides only; runtime remains UNVERIFIED."),
    ):
        child = commands.add_parser(command, help=help_text, description=help_text)
        child.add_argument("--project", required=True, type=Path, help="Exact existing absolute project root; never searches parents.")
    args = parser.parse_args(argv)
    try:
        return initialize(args.project) if args.command == "init" else preflight(args.project)
    except (OSError, ValueError, TypeError, RuntimeError):
        return report(["SETUP_FAILED"], 0)


if __name__ == "__main__":
    raise SystemExit(main())
