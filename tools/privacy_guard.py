"""Fail-closed, digest-scoped tool policy; not a sandbox or a content scanner.

Human approval attests to review, not safety. File changes require fresh approval.
Policy checks do not establish that a client actually invokes this hook. Reviewed
tasks execute mutable local code with the caller's privileges; output suppression
does not prevent network access, credential access, or other child side effects.
Bare and functions.-qualified built-ins share the same checks. Native grep's
singular path is an explicit-file alias, never a default directory or glob.
Installed agent profiles do not grant delegation or other tool capabilities.
"""

import argparse
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import unicodedata
import uuid


POLICY_PATH = Path(".copilot-privacy") / "policy.json"
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
TASK_TIMEOUT_SECONDS = 60
TASK_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,40}\Z", re.ASCII)
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
CONTROL_PARTS = {
    ".copilot-privacy", ".copilot", ".github", ".vscode", ".git",
    "hooks", "agents", "skills",
}
CONTROL_NAMES = {
    "agents.md", "copilot-instructions.md", "plugin.json", "hooks.json",
    "privacy_guard.py",
}


class PolicyError(Exception):
    """Contains a fixed reason code only."""


def fail(code):
    raise PolicyError(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("DUPLICATE_KEY")
        result[key] = value
    return result


def _constant(_value):
    fail("INVALID_JSON")


def parse_json(raw):
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="strict")
        if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
            fail("INPUT_LIMIT")
        return json.loads(
            raw.decode("utf-8-sig", errors="strict"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        fail("INVALID_JSON")


def _text(value, *, nonempty=True):
    if not isinstance(value, str) or "\0" in value or (nonempty and not value.strip()):
        fail("INVALID_VALUE")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        fail("INVALID_VALUE")
    return value


def _keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value):
        fail("INVALID_FIELDS")
    if set(value) - set(required) - set(optional):
        fail("INVALID_FIELDS")


def _no_links(path):
    # lstat every ancestor: resolving first would hide junctions and symlinks.
    for candidate in reversed((path, *path.parents)):
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            fail("LINK_PATH")
    return path


def project_root(value):
    _text(str(value))
    path = Path(value)
    if not path.is_absolute() or any(part in (".", "..") for part in str(value).replace("/", "\\").split("\\")):
        fail("INVALID_PROJECT")
    if path.drive.startswith("\\\\"):
        fail("INVALID_PROJECT")
    _no_links(path)
    if not path.is_dir():
        fail("INVALID_PROJECT")
    return path


def _parts(value):
    _text(value)
    if ntpath.isabs(value) or ntpath.splitdrive(value)[0] or "/" in value:
        fail("INVALID_PATH")
    parts = value.split("\\")
    reserved = re.compile(r"(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)", re.I)
    for part in parts:
        if (
            not part or part in (".", "..") or part[-1] in (".", " ")
            or part.startswith("-") or any(ord(char) < 32 for char in part)
            or any(char in '<>:"|?*' for char in part)
            or "~" in part or reserved.match(part)
            or unicodedata.normalize("NFC", part) != part
        ):
            fail("INVALID_PATH")
    return parts


def canonical_path(value):
    return "\\".join(_parts(value)).casefold()


def _inside(path, parent):
    try:
        return os.path.commonpath((str(path), str(parent))).casefold() == str(parent).casefold()
    except ValueError:
        return False


def classified_path(root, relative):
    parts = _parts(relative)
    if any(part.casefold() in CONTROL_PARTS for part in parts) or parts[-1].casefold() in CONTROL_NAMES:
        fail("CONTROL_PATH")
    path = root.joinpath(*parts)
    if _inside(path, PLUGIN_ROOT):
        fail("CONTROL_PATH")
    _no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("NOT_REGULAR_FILE")
    if not _inside(path.resolve(strict=True), root.resolve(strict=True)):
        fail("OUTSIDE_PROJECT")
    return path


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        while chunk := stream.read(65536):
            result.update(chunk)
        after = os.fstat(stream.fileno())
    current = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or identity(after) != identity(current):
        fail("FILE_CHANGED")
    return result.hexdigest()


def empty_policy():
    return {"version": 1, "files": [], "tasks": {}}


def validate_policy(policy):
    _keys(policy, ("version", "files", "tasks"))
    if type(policy["version"]) is not int or policy["version"] != 1:
        fail("INVALID_VERSION")
    if not isinstance(policy["files"], list) or not isinstance(policy["tasks"], dict):
        fail("INVALID_POLICY")
    seen = set()
    for entry in policy["files"]:
        _keys(entry, ("path", "category", "sha256"))
        key = canonical_path(entry["path"])
        if key in seen:
            fail("DUPLICATE_PATH")
        seen.add(key)
        parts = _parts(entry["path"])
        if any(part.casefold() in CONTROL_PARTS for part in parts) or parts[-1].casefold() in CONTROL_NAMES:
            fail("CONTROL_PATH")
        if not isinstance(entry["category"], str) or entry["category"] not in ("source", "synthetic"):
            fail("INVALID_CATEGORY")
        if not isinstance(entry["sha256"], str) or not HASH_PATTERN.fullmatch(entry["sha256"]):
            fail("INVALID_DIGEST")
    for name, task in policy["tasks"].items():
        if not isinstance(name, str) or not TASK_PATTERN.fullmatch(name):
            fail("INVALID_TASK")
        _keys(task, ("argv", "reviewed"))
        if task["reviewed"] is not True:
            fail("TASK_NOT_REVIEWED")
        if not isinstance(task["argv"], list) or not task["argv"]:
            fail("INVALID_TASK")
        for argument in task["argv"]:
            _text(argument)
    return policy


def load_policy(root):
    root = project_root(root)
    location = _no_links(root / POLICY_PATH)
    if not location.is_file() or location.stat().st_nlink != 1:
        fail("INVALID_POLICY")
    with location.open("rb") as stream:
        policy = validate_policy(parse_json(stream.read(MAX_INPUT_BYTES + 1)))
    for entry in policy["files"]:
        if _inside(root.joinpath(*_parts(entry["path"])), PLUGIN_ROOT):
            fail("CONTROL_PATH")
    return policy


def verify_files(root, policy):
    for entry in policy["files"]:
        if digest(classified_path(root, entry["path"])) != entry["sha256"]:
            fail("STALE_DIGEST")


def _relative_tool_path(root, value):
    _text(value)
    if ntpath.isabs(value) or Path(value).is_absolute():
        path = Path(value)
        if not path.is_absolute() or not _inside(path, root):
            fail("OUTSIDE_PROJECT")
        try:
            value = str(path.relative_to(root)).replace(os.sep, "\\")
        except ValueError:
            fail("OUTSIDE_PROJECT")
    return value


def approved_file(root, policy, value):
    relative = _relative_tool_path(root, value)
    key = canonical_path(relative)
    entry = next((entry for entry in policy["files"] if canonical_path(entry["path"]) == key), None)
    if entry is None:
        fail("UNCLASSIFIED_FILE")
    # Check the requested spelling too, so Windows aliases cannot redirect access.
    path = classified_path(root, relative)
    if digest(path) != entry["sha256"]:
        fail("STALE_DIGEST")
    return path


def runner_command(task):
    if not isinstance(task, str) or not TASK_PATTERN.fullmatch(task):
        fail("INVALID_TASK")
    location = str(Path(__file__).resolve()).replace("'", "''")
    return f"python -I '{location}' run --task {task}"


def deny(code):
    return {"permissionDecision": "deny", "permissionDecisionReason": code}


def _bools(arguments, names):
    for name in names:
        if name in arguments and type(arguments[name]) is not bool:
            fail("INVALID_ARGUMENTS")


def tool_decision(payload):
    _keys(payload, ("toolName", "toolArgs", "cwd"))
    root = project_root(_text(payload["cwd"]))
    policy = load_policy(root)
    name = _text(payload["toolName"])
    known = {"ask_user", "view", "edit", "create", "rg", "grep", "powershell"}
    if name.startswith("functions.") and name[10:] in known:
        name = name[10:]
    if name not in known:
        fail("TOOL_DENIED")
    arguments = payload["toolArgs"]
    if isinstance(arguments, str):
        arguments = parse_json(arguments)
    if not isinstance(arguments, dict):
        fail("INVALID_ARGUMENTS")
    if name == "ask_user":
        _keys(arguments, ("question",), ("choices", "allow_freeform"))
        _text(arguments["question"])
        if "choices" in arguments:
            if not isinstance(arguments["choices"], list):
                fail("INVALID_ARGUMENTS")
            for choice in arguments["choices"]:
                _text(choice)
        _bools(arguments, ("allow_freeform",))
    elif name == "view":
        _keys(arguments, ("path",), ("view_range", "forceReadLargeFiles"))
        approved_file(root, policy, arguments["path"])
        _bools(arguments, ("forceReadLargeFiles",))
        if "view_range" in arguments:
            limits = arguments["view_range"]
            if (
                not isinstance(limits, list) or len(limits) != 2
                or any(type(value) is not int for value in limits)
                or limits[0] < 1 or (limits[1] != -1 and limits[1] < limits[0])
            ):
                fail("INVALID_ARGUMENTS")
    elif name in ("edit", "create"):
        fields = ("path", "old_str", "new_str") if name == "edit" else ("path", "file_text")
        _keys(arguments, fields)
        approved_file(root, policy, arguments["path"])
        for key in fields[1:]:
            _text(arguments[key], nonempty=key == "old_str")
    elif name in ("rg", "grep"):
        _keys(arguments, ("pattern",), (
            "paths", *(("path",) if name == "grep" else ()),
            "output_mode", "-i", "-n", "-A", "-B", "-C", "head_limit", "multiline",
        ))
        if _text(arguments["pattern"]).startswith("-"):
            fail("INVALID_ARGUMENTS")
        if ("paths" in arguments) == ("path" in arguments):
            fail("INVALID_ARGUMENTS")
        if "path" in arguments and not isinstance(arguments["path"], str):
            fail("INVALID_ARGUMENTS")
        paths = arguments.get("paths", arguments.get("path"))
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths:
            fail("INVALID_ARGUMENTS")
        for path in paths:
            approved_file(root, policy, path)
        _bools(arguments, ("-i", "-n", "multiline"))
        if "output_mode" in arguments and arguments["output_mode"] not in ("content", "files_with_matches", "count"):
            fail("INVALID_ARGUMENTS")
        for key in ("-A", "-B", "-C", "head_limit"):
            if key in arguments and (type(arguments[key]) is not int or not 0 <= arguments[key] <= 10000):
                fail("INVALID_ARGUMENTS")
    elif name == "powershell":
        _keys(arguments, ("command",), ("description", "initial_wait", "mode", "detach"))
        if arguments.get("mode", "sync") != "sync" or arguments.get("detach", False) is not False:
            fail("SHELL_DENIED")
        if "description" in arguments:
            _text(arguments["description"])
        if "initial_wait" in arguments and (type(arguments["initial_wait"]) is not int or not 30 <= arguments["initial_wait"] <= 600):
            fail("INVALID_ARGUMENTS")
        command = _text(arguments["command"])
        if not any(command == runner_command(task) for task in policy["tasks"]):
            fail("SHELL_DENIED")
        verify_files(root, policy)
    return {}


def hook(raw):
    try:
        return tool_decision(parse_json(raw))
    except PolicyError as error:
        return deny(str(error))
    except Exception:
        return deny("POLICY_ERROR")


def approve(project, relative, category, reviewed=False):
    if reviewed is not True:
        fail("HUMAN_REVIEW_REQUIRED")
    if category not in ("source", "synthetic"):
        fail("INVALID_CATEGORY")
    root = project_root(project)
    policy = load_policy(root)
    target = classified_path(root, relative)
    entry = {"path": relative, "category": category, "sha256": digest(target)}
    key = canonical_path(relative)
    policy["files"] = [item for item in policy["files"] if canonical_path(item["path"]) != key] + [entry]
    validate_policy(policy)
    raw = (json.dumps(policy, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    if len(raw) > MAX_INPUT_BYTES:
        fail("INPUT_LIMIT")
    directory = _no_links(root / POLICY_PATH.parent)
    destination = _no_links(root / POLICY_PATH)
    scratch = directory / ("update-" + uuid.uuid4().hex)
    try:
        with scratch.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(scratch, destination)
    finally:
        scratch.unlink(missing_ok=True)
    return {"status": "approved", "reason": "HUMAN_ATTESTATION_NOT_SAFETY_PROOF"}


def check(project):
    root = project_root(project)
    policy = load_policy(root)
    verify_files(root, policy)
    return {
        "status": "ok", "reason": "POLICY_CHECK_ONLY",
        "files": len(policy["files"]), "tasks": len(policy["tasks"]),
    }


def run_task(name):
    if not isinstance(name, str) or not TASK_PATTERN.fullmatch(name):
        fail("INVALID_TASK")
    root = project_root(Path.cwd())
    policy = load_policy(root)
    verify_files(root, policy)
    if name not in policy["tasks"]:
        fail("TASK_DENIED")
    child = None
    result = {"task": name, "status": "failure", "exit_code": None}
    try:
        child = subprocess.Popen(
            policy["tasks"][name]["argv"], cwd=root,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, shell=False,
        )
        exceeded = threading.Event()
        captured = bytearray()

        def capture():
            try:
                while chunk := child.stdout.read(8192):
                    remaining = MAX_OUTPUT_BYTES - len(captured)
                    captured.extend(chunk[:max(0, remaining)])
                    if len(chunk) > remaining:
                        exceeded.set()
                        child.kill()
                        break
            except Exception:
                exceeded.set()

        reader = threading.Thread(target=capture, daemon=True)
        reader.start()
        try:
            code = child.wait(timeout=TASK_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            child.kill()
            code = child.wait(timeout=5)
            exceeded.set()
        reader.join(timeout=2)
        if reader.is_alive():
            exceeded.set()
        else:
            child.stdout.close()
        captured.clear()
        result["exit_code"] = code
        result["status"] = "success" if code == 0 and not exceeded.is_set() else "failure"
    except Exception:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        fail("INVALID_CLI")


def main(argv=None):
    try:
        parser = _Parser(add_help=False)
        commands = parser.add_subparsers(dest="action", required=True, parser_class=_Parser)
        commands.add_parser("hook", add_help=False)
        approval = commands.add_parser("approve", add_help=False)
        approval.add_argument("--project", required=True)
        approval.add_argument("--path", required=True)
        approval.add_argument("--category", required=True, choices=("source", "synthetic"))
        approval.add_argument("--reviewed", required=True, action="store_true")
        checking = commands.add_parser("check", add_help=False)
        checking.add_argument("--project", required=True)
        running = commands.add_parser("run", add_help=False)
        running.add_argument("--task", required=True)
        options = parser.parse_args(argv)
        if options.action == "hook":
            result = hook(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
            code = 0
        elif options.action == "approve":
            result = approve(options.project, options.path, options.category, options.reviewed)
            code = 0
        elif options.action == "check":
            result = check(options.project)
            code = 0
        else:
            result = run_task(options.task)
            code = 0 if result["status"] == "success" else 1
    except PolicyError as error:
        result = {"status": "error", "reason": str(error)}
        code = 1
    except Exception:
        result = {"status": "error", "reason": "POLICY_ERROR"}
        code = 1
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
