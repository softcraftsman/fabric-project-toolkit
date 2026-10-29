"""Project-root trust with digest-scoped external access; not a content scanner.

Project files need no inventory. External file changes require fresh approval.
Policy checks do not establish that a client actually invokes this hook. Reviewed
tasks execute mutable local code with the caller's privileges; output suppression
does not prevent network access, credential access, or other child side effects.
Bare and functions.-qualified built-ins share the same checks. Repository
discovery rejects filesystem aliases; local history requires project scope.
Named Fabric agents/skills and documentation have constrained grants; child
hook inheritance and fetch redirects require independent client verification.
"""

import argparse
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import threading
import unicodedata
import uuid
from urllib.parse import urlsplit


POLICY_PATH = Path(".copilot-privacy") / "policy.json"
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SEARCH_ENTRIES = 50000
TASK_TIMEOUT_SECONDS = 60
TASK_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,40}\Z", re.ASCII)
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
CONTROL_PARTS = {
    ".copilot-privacy", ".copilot", ".github", ".vscode", ".git",
    "hooks", "agents", "skills",
}
CONTROL_NAMES = {
    "agents.md", "copilot-instructions.md", "plugin.json", "hooks.json",
    "privacy_guard.py", "mcp-config.json", ".mcp.json",
}
FABRIC_AGENTS = {
    "delivery-lead", "solution-architect", "data-pipeline-engineer",
    "fabric-operator", "semantic-model-engineer", "application-ai-engineer",
    "quality-engineer", "independent-reviewer", "notebook-enablement-author",
}
FABRIC_SKILLS = {
    "spark-cli", "sqldw-cli", "sqldb-cli", "pipeline-migration",
    "dataflows-cli", "eventhouse-cli", "eventstream-cli", "eventschemaset-cli",
    "activator-cli", "semantic-model-authoring", "fabriciq",
    "fabriciq-ontology-cli", "variable-library-cli",
    "git-integration-operations-cli", "deployment-pipelines-authoring-cli",
    "onelake-catalog-govern-cli", "search-consumption-cli",
    "azmon-mirroredcatalogs-operations-cli", "e2e-medallion-architecture",
    "e2e-fabric-cost-estimation", "databricks-migration", "synapse-migration",
    "hdinsight-migration",
}
DELEGATION_RULES = (
    "Follow project AGENTS.md and the privacy hook; do not bypass denials. "
    "Do not execute business-row queries or request business-data output. "
    "Offer an unexecuted read-only query/script for the user to run and analyze. "
    "Use only permitted schema knowledge. Delegate only to this plugin's Fabric "
    "agents with these same rules. No policy changes or expanded permissions."
)
FABRIC_MCP_ARGUMENTS = {
    "docs_list-item-types": ((), ()),
    "docs_platform-api-spec": ((), ()),
    "docs_item-api-spec": (("item-type",), ()),
    "docs_item-definitions": (("item-type",), ()),
    "docs_api-examples": (("item-type",), ()),
    "docs_best-practices": (("topic",), ()),
    "core_list-workspaces": ((), ("roles", "continuation-token", "prefer-workspace-specific-endpoints")),
    "core_list-items": (("workspace-id",), ("type", "recursive", "root-folder-id", "continuation-token")),
    "core_get-item": (("workspace-id", "item-id"), ()),
    "core_list-capacities": ((), ("continuation-token",)),
    "core_get-capacity": (("capacity-id",), ()),
    "onelake_list-table-namespaces": (("workspace-id", "item-id"), ()),
    "onelake_list-tables": (("workspace-id", "item-id", "namespace"), ()),
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
    _text(value)
    path = Path(value)
    if path.is_absolute():
        if path.drive.startswith("\\\\"):
            fail("INVALID_PATH")
        return (path.anchor + "\\".join(_parts(str(path.relative_to(path.anchor)).replace(os.sep, "\\")))).casefold()
    return "\\".join(_parts(value)).casefold()


def _inside(path, parent):
    try:
        return os.path.commonpath((str(path), str(parent))).casefold() == str(parent).casefold()
    except ValueError:
        return False


def classified_path(root, relative, *, allow_missing=False, read_only=False):
    relative = _relative_tool_path(root, relative)
    absolute = Path(relative)
    external = absolute.is_absolute()
    parts = _parts(
        str(absolute.relative_to(absolute.anchor)).replace(os.sep, "\\")
        if external else relative
    )
    if not (read_only and not external) and (
        any(part.casefold() in CONTROL_PARTS for part in parts)
        or parts[-1].casefold() in CONTROL_NAMES
    ):
        fail("CONTROL_PATH")
    if external and absolute.drive.startswith("\\\\"):
        fail("INVALID_PATH")
    path = absolute if external else root.joinpath(*parts)
    if _inside(path, PLUGIN_ROOT) and not (read_only and not external):
        fail("CONTROL_PATH")
    if allow_missing and not external and not path.exists():
        try:
            _no_links(path)
        except FileNotFoundError:
            _no_links(path.parent)
            if not path.parent.is_dir():
                fail("INVALID_PATH")
            return path
    _no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("NOT_REGULAR_FILE")
    if not external and not _inside(path.resolve(strict=True), root.resolve(strict=True)):
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
        entry_path = Path(entry["path"])
        parts = _parts(
            str(entry_path.relative_to(entry_path.anchor)).replace(os.sep, "\\")
            if entry_path.is_absolute() else entry["path"]
        )
        if any(part.casefold() in CONTROL_PARTS for part in parts) or parts[-1].casefold() in CONTROL_NAMES:
            fail("CONTROL_PATH")
        if not isinstance(entry["category"], str) or entry["category"] not in ("source", "synthetic"):
            fail("INVALID_CATEGORY")
        if not isinstance(entry["sha256"], str) or not HASH_PATTERN.fullmatch(entry["sha256"]):
            fail("INVALID_DIGEST")
    for name, task in policy["tasks"].items():
        if not isinstance(name, str) or not TASK_PATTERN.fullmatch(name):
            fail("INVALID_TASK")
        _keys(task, ("argv", "reviewed"), ("output", "synthetic_only"))
        if task["reviewed"] is not True:
            fail("TASK_NOT_REVIEWED")
        if not isinstance(task["argv"], list) or not task["argv"]:
            fail("INVALID_TASK")
        for argument in task["argv"]:
            _text(argument)
        if task.get("output", "status") not in ("status", "diagnostics"):
            fail("INVALID_TASK")
        if "synthetic_only" in task and type(task["synthetic_only"]) is not bool:
            fail("INVALID_TASK")
        if task.get("output") == "diagnostics" and task.get("synthetic_only") is not True:
            fail("SYNTHETIC_ATTESTATION_REQUIRED")
    return policy


def load_policy(root):
    root = project_root(root)
    location = _no_links(root / POLICY_PATH)
    if not location.is_file() or location.stat().st_nlink != 1:
        fail("INVALID_POLICY")
    with location.open("rb") as stream:
        policy = validate_policy(parse_json(stream.read(MAX_INPUT_BYTES + 1)))
    for entry in policy["files"]:
        relative = _relative_tool_path(root, entry["path"])
        target = Path(relative) if Path(relative).is_absolute() else root.joinpath(*_parts(relative))
        if _inside(target, PLUGIN_ROOT):
            fail("CONTROL_PATH")
    return policy


def verify_files(root, policy):
    for entry in policy["files"]:
        if not Path(_relative_tool_path(root, entry["path"])).is_absolute():
            continue
        if digest(classified_path(root, entry["path"])) != entry["sha256"]:
            fail("STALE_DIGEST")


def _relative_tool_path(root, value):
    _text(value)
    if ntpath.isabs(value) or Path(value).is_absolute():
        path = Path(value)
        canonical_path(value)
        if not path.is_absolute():
            fail("INVALID_PATH")
        if not _inside(path, root):
            return value
        try:
            value = str(path.relative_to(root)).replace(os.sep, "\\")
        except ValueError:
            fail("OUTSIDE_PROJECT")
    return value


def approved_file(root, policy, value, *, allow_missing=False, read_only=False):
    relative = _relative_tool_path(root, _text(value).replace("/", "\\"))
    # Validate controls and filesystem aliases even for trusted project files.
    path = classified_path(root, relative, allow_missing=allow_missing, read_only=read_only)
    if not Path(relative).is_absolute():
        return path
    key = canonical_path(relative)
    entry = next((entry for entry in policy["files"] if canonical_path(entry["path"]) == key), None)
    if entry is None:
        fail("UNCLASSIFIED_FILE")
    if digest(path) != entry["sha256"]:
        fail("STALE_DIGEST")
    return path


def repository_path(root, value):
    value = _text(value).replace("/", "\\")
    if value == "." or value.casefold() == str(root).casefold():
        return root
    relative = _relative_tool_path(root, value)
    if Path(relative).is_absolute():
        fail("OUTSIDE_PROJECT")
    path = root.joinpath(*_parts(relative))
    _no_links(path)
    if not _inside(path.resolve(strict=True), root.resolve(strict=True)):
        fail("OUTSIDE_PROJECT")
    return path


def readable_tree(root, path):
    # Native discovery tools cannot be rewritten by a hook. Check their entire
    # possible input tree before allowing them, without opening file contents.
    pending = [path]
    count = 0
    while pending:
        current = pending.pop()
        _no_links(current)
        info = current.stat()
        count += 1
        if count > MAX_SEARCH_ENTRIES:
            fail("SEARCH_SCOPE_LIMIT")
        if stat.S_ISDIR(info.st_mode):
            pending.extend(current.iterdir())
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail("NOT_REGULAR_FILE")


def search_path(root, policy, value):
    value = _text(value).replace("/", "\\")
    relative = _relative_tool_path(root, value)
    if Path(relative).is_absolute():
        approved_file(root, policy, value, read_only=True)
    else:
        readable_tree(root, repository_path(root, value))


def glob_pattern(value):
    value = _text(value).replace("/", "\\")
    if ntpath.isabs(value) or ntpath.splitdrive(value)[0]:
        fail("INVALID_PATH")
    # Only ordinary components plus * and ?; no traversal, brace alternatives,
    # extglobs or character classes that might change the apparent scope.
    _parts(value.replace("*", "x").replace("?", "x"))
    if any(char in value for char in "[]{}!"):
        fail("INVALID_PATH")


def history_query(root, arguments):
    _keys(arguments, ("query", "description"), ("source",))
    _text(arguments["description"])
    if arguments.get("source") != "local":
        fail("HISTORY_SCOPE_REQUIRED")
    query = _text(arguments["query"]).strip().removesuffix(";")
    token_pattern = re.compile(
        r"\s+|'(?:[^']|'')*'|[a-zA-Z_][a-zA-Z_0-9]*|[0-9]+(?:\.[0-9]+)?|"
        r"<=|>=|<>|!=|==|[(),.*=<>+/%-]"
    )
    tokens = []
    position = 0
    for match in token_pattern.finditer(query):
        if match.start() != position:
            fail("HISTORY_SCOPE_REQUIRED")
        position = match.end()
        if not match[0].isspace():
            tokens.append(match[0])
    if position != len(query) or not tokens:
        fail("HISTORY_SCOPE_REQUIRED")
    lower = [token.lower() if not token.startswith("'") else token for token in tokens]
    if lower[0] != "select" or lower.count("select") != 1 or any(
        token in lower for token in (
            "union", "intersect", "except", "with", "over", "collate",
        )
    ) or "--" in query or "/*" in query:
        fail("HISTORY_SCOPE_REQUIRED")
    try:
        from_index = lower.index("from")
        where_index = lower.index("where", from_index)
    except ValueError:
        fail("HISTORY_SCOPE_REQUIRED")
    relation = " ".join(lower[from_index + 1:where_index])
    identifier = r"[a-z_][a-z_0-9]*"
    single = re.fullmatch(rf"sessions(?: (?:as )?({identifier}))?", relation)
    if single:
        alias = single[1]
        scope_column = [alias, ".", "cwd"] if alias else ["cwd"]
    else:
        joined = re.fullmatch(
            rf"(turns|checkpoints|session_files|session_refs) (?:as )?({identifier}) "
            rf"(?:inner )?join sessions (?:as )?({identifier}) on "
            rf"({identifier}) \. session_id = ({identifier}) \. id", relation,
        )
        if (
            joined is None or joined[2] == joined[3]
            or joined[4] != joined[2] or joined[5] != joined[3]
        ):
            fail("HISTORY_SCOPE_REQUIRED")
        scope_column = [joined[3], ".", "cwd"]
    # Scope must be a top-level AND conjunct. OR is safe only within a separate
    # parenthesized filter, where it cannot widen the mandatory project filter.
    conjuncts = []
    start = where_index + 1
    depth = 0
    for index in range(start, len(tokens)):
        token = lower[index]
        if depth == 0:
            if token in ("group", "order", "limit"):
                conjuncts.append(tokens[start:index])
                break
            if token == "or":
                fail("HISTORY_SCOPE_REQUIRED")
            if token == "and":
                conjuncts.append(tokens[start:index])
                start = index + 1
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        if depth < 0:
            fail("HISTORY_SCOPE_REQUIRED")
    else:
        conjuncts.append(tokens[start:])
    expected = "'" + str(root).replace("'", "''") + "'"
    if not any(
        [token.lower() if not token.startswith("'") else token for token in clause]
        == scope_column + ["=", expected]
        for clause in conjuncts
    ):
        fail("HISTORY_SCOPE_REQUIRED")
    # Prepare against an empty schema, never the real history store. SQLite
    # validates expressions; its authorizer blocks non-history reads and unsafe
    # functions. No query is executed, including functions supplied by the agent.
    schema = {
        "sessions": "id summary cwd repository branch created_at updated_at",
        "turns": "session_id turn_index user_message assistant_response timestamp",
        "checkpoints": "session_id checkpoint_number title overview created_at",
        "session_files": "session_id file_path tool_name turn_index first_seen_at",
        "session_refs": "session_id ref_type ref_value turn_index created_at",
    }
    functions = {
        "count", "sum", "avg", "min", "max", "total", "coalesce", "ifnull",
        "nullif", "lower", "upper", "length", "substr", "substring", "instr",
        "trim", "ltrim", "rtrim", "replace", "round", "abs", "like", "glob",
        "date", "datetime", "time", "julianday", "strftime", "unixepoch",
        "group_concat",
    }

    def authorize(action, first, second, _database, _trigger):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and first in schema:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and second.lower() in functions:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    try:
        with sqlite3.connect(":memory:") as database:
            for table, columns in schema.items():
                database.execute(f"CREATE TABLE {table} ({', '.join(columns.split())})")
            database.set_authorizer(authorize)
            database.execute("EXPLAIN " + query)
    except sqlite3.Error:
        fail("HISTORY_SCOPE_REQUIRED")


def runner_command(task):
    if not isinstance(task, str) or not TASK_PATTERN.fullmatch(task):
        fail("INVALID_TASK")
    location = str(Path(__file__).resolve()).replace("'", "''")
    return f"python -I '{location}' run --task {task}"


def directory_command(relative):
    _parts(relative)
    if "'" in relative:
        fail("INVALID_PATH")
    location = str(Path(__file__).resolve()).replace("'", "''")
    return f"python -I '{location}' mkdir --path '{relative}'"


def directory_target(root, relative):
    parts = _parts(relative)
    if (
        any(part.casefold() in CONTROL_PARTS for part in parts)
        or parts[-1].casefold() in CONTROL_NAMES
    ):
        fail("CONTROL_PATH")
    path = root.joinpath(*parts)
    if _inside(path, PLUGIN_ROOT):
        fail("CONTROL_PATH")
    ancestor = path
    while True:
        try:
            ancestor.lstat()
            break
        except FileNotFoundError:
            ancestor = ancestor.parent
    _no_links(ancestor)
    if not ancestor.is_dir():
        fail("INVALID_PATH")
    return path


def make_directory(relative):
    root = project_root(Path.cwd())
    load_policy(root)
    path = directory_target(root, relative)
    path.mkdir(parents=True, exist_ok=True)
    _no_links(path)
    return {"status": "created", "reason": "PROJECT_DIRECTORY"}


def git_inspection(command):
    if any(char in command for char in ";|&`$><\r\n"):
        return False
    tokens = re.findall(r'"[^"]*"|\'[^\']*\'|[^\s"\']+', command)
    if " ".join(tokens) != command or tokens[:2] != ["git", "--no-pager"] or len(tokens) < 3:
        return False
    if tokens[2] not in ("diff", "log"):
        return False
    options = {
        "--cached", "--staged", "--stat", "--name-only", "--name-status",
        "--numstat", "--shortstat", "--summary", "--patch", "-p", "--raw",
        "--oneline", "--graph", "--all", "--decorate", "--no-decorate",
        "--no-ext-diff", "--no-textconv", "--no-color", "--color=never",
        "--full-history", "--reverse", "--date-order", "--topo-order",
        "--no-renames", "--find-renames", "--check",
    }
    after_separator = False
    for token in tokens[3:]:
        if token == "--" and not after_separator:
            after_separator = True
            continue
        if not after_separator and (token in options or re.fullmatch(
            r"(?:-n[0-9]+|--max-count=[0-9]+|--unified=[0-9]+|-[0-9]+)", token
        )):
            continue
        value = token.strip("'\"")
        if after_separator:
            if token[0] not in "'\"" and not re.fullmatch(r"[a-zA-Z0-9_.\\/-]+", token):
                return False
            try:
                _parts(value.replace("/", "\\"))
            except PolicyError:
                return False
        elif not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_./~^-]*", value) or value.startswith("-"):
            return False
    return True


def documentation_request(arguments):
    _keys(arguments, ("url",), ("max_length", "start_index", "raw"))
    url = urlsplit(_text(arguments["url"]))
    if (
        url.scheme != "https" or url.hostname not in (
            "learn.microsoft.com", "docs.microsoft.com", "code.visualstudio.com",
        )
        or url.username is not None or url.password is not None or url.port not in (None, 443)
        or url.query or url.fragment or not url.path.startswith("/")
        or any(char in url.path for char in "\\\r\n")
    ):
        fail("DOCUMENTATION_ONLY")
    for key, maximum in (("max_length", 20000), ("start_index", 1000000)):
        if key in arguments and (
            type(arguments[key]) is not int or not 0 <= arguments[key] <= maximum
        ):
            fail("INVALID_ARGUMENTS")
    _bools(arguments, ("raw",))


def fabric_metadata_request(name, arguments):
    tool = name.removeprefix("fabric-metadata-")
    if tool not in FABRIC_MCP_ARGUMENTS:
        fail("FABRIC_METADATA_ONLY")
    _keys(arguments, *FABRIC_MCP_ARGUMENTS[tool])
    for key, value in arguments.items():
        if key in ("workspace-id", "item-id", "capacity-id", "root-folder-id"):
            if (
                not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", _text(value))
                or uuid.UUID(value).int == 0
            ):
                fail("FABRIC_METADATA_ONLY")
        elif key in ("type", "item-type", "namespace"):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", _text(value)):
                fail("FABRIC_METADATA_ONLY")
        elif key == "topic":
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,79}", _text(value)):
                fail("FABRIC_METADATA_ONLY")
        elif key == "roles":
            if any(role.strip().casefold() not in ("admin", "member", "contributor", "viewer")
                   for role in _text(value).split(",")):
                fail("FABRIC_METADATA_ONLY")
        elif key == "continuation-token":
            if len(_text(value)) > 8192 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                fail("FABRIC_METADATA_ONLY")
        elif key == "recursive":
            if value is not None and type(value) is not bool:
                fail("FABRIC_METADATA_ONLY")
        elif key == "prefer-workspace-specific-endpoints":
            if value is not None and value is not False:
                fail("FABRIC_METADATA_ONLY")


def deny(code):
    return {"permissionDecision": "deny", "permissionDecisionReason": code}


def _bools(arguments, names):
    for name in names:
        if name in arguments and type(arguments[name]) is not bool:
            fail("INVALID_ARGUMENTS")


def tool_decision(payload):
    _keys(payload, ("toolName", "toolArgs", "cwd"), (
        "sessionId", "timestamp", "agentId", "agentType", "parentAgentId",
    ))
    root = project_root(_text(payload["cwd"]))
    policy = load_policy(root)
    name = _text(payload["toolName"])
    known = {
        "ask_user", "view", "edit", "create", "rg", "grep", "glob",
        "session_store_sql", "powershell", "web_fetch", "skill", "task",
    }
    if name.startswith("functions.") and name[10:] in known:
        name = name[10:]
    metadata = name.startswith("fabric-metadata-")
    if name not in known and not metadata:
        fail("TOOL_DENIED")
    arguments = payload["toolArgs"]
    if isinstance(arguments, str):
        arguments = parse_json(arguments)
    if not isinstance(arguments, dict):
        fail("INVALID_ARGUMENTS")
    if metadata:
        fabric_metadata_request(name, arguments)
    elif name == "web_fetch":
        documentation_request(arguments)
    elif name == "skill":
        _keys(arguments, ("skill",))
        if arguments["skill"] not in FABRIC_SKILLS:
            fail("SKILL_DENIED")
    elif name == "task":
        _keys(arguments, ("agent_type", "prompt", "description"), ("name", "mode"))
        if (
            arguments["agent_type"] not in {
                "fabric-project-toolkit:" + agent for agent in FABRIC_AGENTS
            }
            or arguments.get("mode", "sync") != "sync"
            or DELEGATION_RULES not in _text(arguments["prompt"])
        ):
            fail("FABRIC_DELEGATION_REQUIRED")
        _text(arguments["description"])
        if "name" in arguments:
            _text(arguments["name"])
    elif name == "ask_user":
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
        value = _text(arguments["path"]).replace("/", "\\")
        if value == "." or (
            not Path(_relative_tool_path(root, value)).is_absolute()
            and repository_path(root, value).is_dir()
        ):
            readable_tree(root, repository_path(root, value))
        else:
            approved_file(root, policy, value, read_only=True)
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
        approved_file(root, policy, arguments["path"], allow_missing=name == "create")
        for key in fields[1:]:
            _text(arguments[key], nonempty=key == "old_str")
    elif name == "session_store_sql":
        history_query(root, arguments)
    elif name == "glob":
        _keys(arguments, ("pattern",), ("paths",))
        glob_pattern(arguments["pattern"])
        paths = arguments.get("paths", ".")
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths:
            fail("INVALID_ARGUMENTS")
        for value in paths:
            readable_tree(root, repository_path(root, value))
    elif name in ("rg", "grep"):
        _keys(arguments, ("pattern",), (
            "paths", *(("path",) if name == "grep" else ()),
            "output_mode", "-i", "-n", "-A", "-B", "-C", "head_limit", "multiline",
            "glob", "type",
        ))
        if _text(arguments["pattern"]).startswith("-"):
            fail("INVALID_ARGUMENTS")
        if "paths" in arguments and "path" in arguments:
            fail("INVALID_ARGUMENTS")
        if "path" in arguments and not isinstance(arguments["path"], str):
            fail("INVALID_ARGUMENTS")
        paths = arguments.get("paths", arguments.get("path", "."))
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths:
            fail("INVALID_ARGUMENTS")
        for path in paths:
            search_path(root, policy, path)
        if "glob" in arguments:
            glob_pattern(arguments["glob"])
        if "type" in arguments and not re.fullmatch(r"[a-zA-Z0-9_+-]{1,30}", _text(arguments["type"])):
            fail("INVALID_ARGUMENTS")
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
        if git_inspection(command):
            return {}
        prefix = directory_command("placeholder").rsplit("'placeholder'", 1)[0]
        if command.startswith(prefix):
            quoted = command[len(prefix):]
            if len(quoted) < 3 or quoted[0] != "'" or quoted[-1] != "'":
                fail("SHELL_DENIED")
            relative = quoted[1:-1]
            if command != directory_command(relative):
                fail("SHELL_DENIED")
            directory_target(root, relative)
            return {}
        if command in (
            "git --no-pager status --short",
            "git -c core.fsmonitor=false --no-pager status --short",
        ):
            return {}
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
    relative = _relative_tool_path(root, relative)
    if not Path(relative).is_absolute():
        return {"status": "trusted", "reason": "PROJECT_ROOT_TRUSTED"}
    entry = {"path": relative, "category": category, "sha256": digest(target)}
    key = canonical_path(relative)
    policy["files"] = [
        item for item in policy["files"]
        if Path(_relative_tool_path(root, item["path"])).is_absolute()
        and canonical_path(item["path"]) != key
    ] + [entry]
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
            if policy["tasks"][name].get("output") == "diagnostics":
                result["output"] = captured.decode("utf-8", errors="replace")
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
        directory = commands.add_parser("mkdir", add_help=False)
        directory.add_argument("--path", required=True)
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
        elif options.action == "mkdir":
            result = make_directory(options.path)
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
