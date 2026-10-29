# Use cases and access decisions

This inventory describes the current implementation, including project-root
trust and current-project history support. An installed copy only has these
behaviors after it receives the corresponding changes and starts a fresh
session.

**Scope:** native Windows Copilot CLI tool calls with this plugin's hook active
and a valid `.copilot-privacy\policy.json` at the exact session working directory.
The working directory is the policy's project root; the engine does not discover
a parent policy or verify the root against Git.

| Decision | Meaning |
| --- | --- |
| Allowed | The hook does not deny the supported operation. Normal Copilot permissions still apply. |
| Conditional | Allowed only when the stated scope, arguments, or approval requirements are met. |
| Blocked | The hook denies the operation on the supported tool-call path. |
| Not covered | The hook cannot intercept or establish protection for this case. This is not an approval. |

Neither file location nor an approval proves that content is safe. For inference
outside an approved BAA boundary, keep business data and secrets out of the
project, approved external files, prompts, and retrieved history.

## Project files and repository discovery

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Read an ordinary file in the project root | Allowed | No individual policy entry or SHA-256 check. |
| Read files in project subdirectories | Allowed | Same root trust; filesystem-alias checks still apply. |
| Read a project file after it changes | Allowed | Internal content changes do not require reapproval. |
| Read project source, Markdown, notebook JSON, pipeline definitions, or test fixtures | Allowed | No extension/content allowlist; ordinary project files are trusted by location. |
| Read an image or another non-text project file through `view` | Allowed | The policy checks its path, not whether the client can render it or whether it contains sensitive information. |
| Read an export, log, notebook output, secret, or business-data file saved inside the project | Allowed | **Residual risk:** the guard does not inspect or redact project content. Keep sensitive content out of the trusted tree. |
| Read project instructions, `.github`, `.vscode`, `.git`, policy, hook, agent, or plugin files | Allowed | Read-only access is allowed inside the project; edits remain protected. |
| List the project root or a subdirectory using `view` | Conditional | The possible input tree must pass the discovery checks below. |
| Find files using `glob`, such as `docs/**/*Silver*` | Conditional | Search roots must be within the project. Ordinary components, `*`, `?`, and recursive `**` patterns are supported. |
| Search project files or directories with `rg` or `grep` | Conditional | Explicit files/directories or the default current directory; supported arguments only. |
| Search with a glob or file-type filter | Conditional | Ordinary glob syntax; type names limited to 1-30 letters, digits, `_`, `+`, or `-`. |
| Return matching lines, matching file names, or counts | Allowed | Supported search output modes; this is not content redaction. |
| Use case-insensitive, multiline, line-number, or context search options | Conditional | Supported Boolean options; context and result limits must be integers from 0 to 10,000. |
| Use absolute internal paths or relative discovery/read paths | Conditional | Must identify the project or a contained path without traversal. Reads and discovery accept either path separator. |
| Use brace alternatives, character classes, or negated glob patterns | Blocked | Glob filters reject `[`, `]`, `{`, `}`, and `!`. |
| Pass arbitrary search flags, preprocessing commands, or unknown arguments | Blocked | Search arguments are validated; a search expression starting with `-` is rejected. |
| Search/list a tree with more than 50,000 entries | Blocked | The entire possible input tree is checked, not just files matching the filter. Narrow the scope. |
| Search/list a tree containing a link, junction, hard-linked file, or special file | Blocked | The tree is denied even when the requested filter would not match that entry. |
| Depend on Git-ignore rules to protect sensitive files | Not covered | Ignore rules are not this policy's access boundary. |

## File creation and changes

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Edit an existing ordinary project file using `edit` | Allowed | No per-file registration or digest; strict edit arguments. |
| Replace an existing ordinary project file using `create` | Allowed | Same project-root trust. |
| Create a new project file | Conditional | Its parent directory must already exist and pass path checks. |
| Create missing project directories, then files within them | Conditional | Use the installed engine's exact `mkdir --path '<relative-directory>'` wrapper; no external/control paths or links. File creation still requires the parent to exist. |
| Edit `.copilot-privacy`, `.copilot`, `.github`, `.vscode`, `.git`, `hooks`, `agents`, or `skills` paths | Blocked | Protected component names apply at any depth, case-insensitively. |
| Edit `AGENTS.md`, `copilot-instructions.md`, `plugin.json`, `hooks.json`, `privacy_guard.py`, `mcp-config.json`, or `.mcp.json` | Blocked | Protected file names apply at any depth, case-insensitively. |
| Edit the installed plugin package | Blocked | Plugin implementation is not an ordinary editable target. |
| Have the agent approve its own files or widen policy | Blocked | No ordinary agent approval command or policy-edit grant. |
| Delete, rename, or move files through a general-purpose tool | Blocked | No such tool is allowlisted; `edit` does not accept a move argument. Reviewed tasks can have separate side effects. |
| Use `apply_patch`, including for otherwise trusted source files | Blocked | This baseline allows `edit`/`create`, not arbitrary patch payloads. |

## External files and filesystem boundaries

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Read or search an external file with no approval | Blocked | Project-root trust does not extend outside the root. |
| Read or search an approved external file | Conditional | Individual source/synthetic approval, absolute file path, and matching SHA-256 digest. |
| Edit or overwrite an approved external file | Conditional | The existing file's digest must match before the operation. |
| Read/search/edit an external file after any change, including an agent edit | Blocked | A human must review and approve its new digest first. |
| Create a nonexistent external file | Blocked | External approval requires an existing regular file. |
| Approve an external directory or search it recursively | Blocked | External grants apply to individual files, not folders or globs. |
| Approve external control files or files in the installed plugin package | Blocked | Approval does not override protected control paths. |
| Approve an external file without `--reviewed` | Blocked | Human attestation is required. |
| Approve an ordinary internal file | Allowed | Returns `PROJECT_ROOT_TRUSTED`; no entry or hash is added. Protected control paths are not eligible. |
| Grant access by extension or directory name alone | Blocked | External grants require individual review and digest verification. |
| Access `..`, dot-component aliases, alternate data streams, short-name aliases, reserved device names, or malformed paths | Blocked | Strict Windows path checks; ordinary discovery roots may use `.`. |
| Access a sibling directory whose name starts with the project's name | Blocked | It is external, not contained by the project prefix. An individual eligible file can be approved separately. |
| Access a symlink, junction, reparse-point path, or hard-linked file | Blocked | Local aliases do not inherit project trust or bypass external approval. |
| Use a UNC/network-share project root or external approval | Blocked | Not a supported path scope. |
| Replace files concurrently after a check | Not covered | Checks are not atomic with the client's subsequent tool execution. |

## Session history

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Discover/search sessions for the exact current project directory | Allowed | Use `source: "local"` and the exact project `cwd` equality as a top-level AND condition. No individual approval. |
| Read current-project prompts and assistant responses | Conditional | Supported `turns` join through `sessions`, filtered by exact project `cwd`. |
| Read current-project checkpoints | Conditional | Supported `checkpoints` join; descending `t.created_at`. |
| Read current-project changed-file metadata | Conditional | Supported `session_files` join; descending `t.first_seen_at`. |
| Read current-project PR, issue, or commit references | Conditional | Supported `session_refs` join; descending `t.created_at`. |
| Search transcripts/summaries with text, time, or session-ID filters | Allowed | Keep project scope; group OR alternatives in parentheses after AND. |
| Retrieve wildcard columns, aggregates, grouped results, or more than 100 rows | Allowed | No plugin row cap or mandatory ordering; optional LIMIT/OFFSET and common SQLite functions. The tool can impose its own result limits. |
| Retrieve another project's sessions | Blocked | Exact project-directory comparison, not a Git-remote or path-prefix match. |
| Retrieve a different clone, worktree, or subdirectory session as the same project | Blocked | It has a different `cwd`, even if the repository remote matches. |
| Retrieve history by session ID without the project join/filter | Blocked | A known ID alone does not establish project scope. |
| Query without `source`, or with `source: "cloud"` | Blocked | Explicit local-only retrieval is required. |
| Query raw events, tool requests, attachments, usage, or arbitrary tables | Blocked | Only sessions and the four named joined tables are supported. |
| Use unions, subqueries, window functions, arbitrary functions, or multiple statements | Blocked | Scoped SELECT subset with syntax/function validation. A single trailing semicolon is accepted. |
| Write to the history database or load SQL extensions | Blocked | Read-only history searches only. |
| Retrieve history that exists only in the cloud | Blocked | This path does not fetch it. |
| Read old business data already present in current-project history | Allowed | **Residual risk:** project filtering is not transcript scanning or redaction. |
| Resume a session or receive automatic history/context outside a tool call | Not covered | The tool-query gate does not screen automatic context ingestion. |

Example queries, using `source: "local"` (not fixed templates):

```sql
SELECT id, summary, updated_at FROM sessions
WHERE cwd = '<exact-project-root>'
ORDER BY updated_at DESC LIMIT 20
```

```sql
SELECT t.session_id, t.user_message, t.assistant_response FROM turns AS t
JOIN sessions AS s ON t.session_id = s.id
WHERE s.cwd = '<exact-project-root>'
AND (t.user_message LIKE '%silver%' OR t.assistant_response LIKE '%silver%')
ORDER BY t.timestamp DESC LIMIT 50
```

Substitute the actual root and escape SQL apostrophes as `''`. The allowed
session columns are `id`, `summary`, `cwd`, `repository`, `branch`, `created_at`,
and `updated_at`. Wildcards and expressions over supported columns are allowed.
Aliases are optional for `sessions` and customizable for joined queries.
Ordering and pagination are optional; the following are useful time columns:

| Joined table | Available history columns | Suggested time column |
| --- | --- | --- |
| `turns` | `session_id`, `turn_index`, `user_message`, `assistant_response`, `timestamp` | `t.timestamp` |
| `checkpoints` | `session_id`, `checkpoint_number`, `title`, `overview`, `created_at` | `t.created_at` |
| `session_files` | `session_id`, `file_path`, `tool_name`, `turn_index`, `first_seen_at` | `t.first_seen_at` |
| `session_refs` | `session_id`, `ref_type`, `ref_value`, `turn_index`, `created_at` | `t.created_at` |

## Shell, Git, and development tasks

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Run `git --no-pager status --short` through `powershell` | Allowed | Exact command, synchronous, not detached. Git configuration/helpers remain a local execution risk. |
| Run `git -c core.fsmonitor=false --no-pager status --short` | Allowed | Exact alternative disables the fsmonitor helper for this operation. |
| Inspect full Git diffs/logs | Conditional | `git --no-pager diff` or `git --no-pager log`, supported display flags, revision ranges and relative paths after `--`. Output is not redacted; Git configuration/helpers remain trusted local code. Prefer `--no-ext-diff --no-textconv` for diffs. |
| Run Git show, fetch, commit, push, or GitHub CLI commands directly | Blocked | No general Git/GitHub shell allowlist. A human can separately review a fixed task. |
| Append commands, pipes, or unlisted options to an allowed command | Blocked | Validated command shape; no shell expansion grant. |
| Run an arbitrary PowerShell command, script, Python program, SQL query, or notebook directly | Blocked | Outside the reviewed task wrapper. |
| Run a named, human-reviewed development task | Conditional | Exact installed-wrapper command, valid task policy, synchronous execution, and valid external digests. |
| Run approved tests, builds, formatters, or linters | Conditional | Fixed reviewed task; review code, imports, fixtures, configuration, executable, and side effects. |
| Return task pass/fail and exit-code metadata | Allowed | All tasks retain status/exit-code results; default output mode is status-only. |
| Diagnose a failed local test from assertions, tracebacks, or test output | Conditional | Human-reviewed task with `output: "diagnostics"` and `synthetic_only: true`; no business data or live-data credentials. Captured stdout/stderr is bounded to 1 MiB. The flag is attestation, not scanning. |
| Return child output from a default/status-only task | Blocked | Output remains suppressed; synthetic diagnostics must be explicitly configured. Files written inside the trusted project remain independently readable. |
| Start asynchronous/detached shell work | Blocked | The supported shell path requires synchronous, attached execution. |
| Use Bash or shell follow-up/session-management tools | Blocked | Not in the supported tool allowlist. |
| Execute a task not marked `reviewed: true`, or with an invalid name/argument list | Blocked | Invalid task policy is rejected. |
| Execute a task after an approved external file drifts | Blocked | External inventory is checked before task execution. |
| Have a reviewed task read data, use credentials, write files, or access the network | Not covered | The task runs with the user's privileges; output capture is not a sandbox. |
| Have a task run indefinitely or emit unlimited captured output | Blocked | The runner bounds its direct child to 60 seconds and 1 MiB captured output; this is not process-tree isolation. |

Exact task command:

```powershell
python -I '<installed-plugin-root>\tools\privacy_guard.py' run --task <reviewed-task-name>
```

## Fabric, integrations, and agents

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Select any of the nine bundled Fabric solution-building roles | Allowed | Role selection does not grant extra tool or data permissions. |
| Read/edit eligible local Fabric solution code and definitions | Conditional | Project-root rules or external approval rules apply. |
| Discover live workspaces, items, capacities, OneLake namespaces and table names | Conditional | Only the 7 named inventory tools on the pinned `fabric-metadata` server. Exact arguments and UUID scopes; no friendly-name aliases or endpoint overrides. See the [tool policy](README.md#fabric-metadata-mcp-policy). |
| Read Fabric API specifications, item definition documentation, examples and best practices through MCP | Conditional | Only the 6 named offline `docs_*` tools on `fabric-metadata`; these do not retrieve live item definitions. |
| Inspect full live item/table/model definitions or report metadata | Blocked | Full definitions, raw table metadata, business literals, filters, annotations and verified answers are not approved. Column-level inspection remains deferred. |
| Query Lakehouse, Warehouse, SQL endpoints, OneLake, semantic models, or reports through MCP | Blocked | SQL/DAX/KQL/M and value-search tools remain denied, including aggregate queries. |
| Use another MCP server or call a new tool introduced by an upgrade | Blocked | No server-wide or suffix-based approval. The package is pinned; only 13 exact tool names and supported arguments are accepted. |
| Retrieve descriptions/tags or sensitive names through an allowed inventory tool | Not covered | Results and service errors are not redacted. Use only a curated technical-metadata environment and least-privilege credentials. |
| Restrict MCP discovery to project-specific Fabric workspace IDs | Not covered | Discovery follows the server identity's Fabric permissions; no project workspace allowlist is implemented. |
| Read live Fabric notebook outputs/run results through a connector | Blocked | Inventory approval does not grant outputs or operation-result tools. A saved local file follows file-location rules instead. |
| Deploy or execute Fabric workloads through an operator agent | Blocked | The role exists, but live deployment tools have no baseline grant. Reviewed tasks are a separate execution path. |
| Delegate to a bundled Fabric agent | Conditional | Synchronous `task` to an exact `fabric-project-toolkit:<role>` with the full AGENTS.md handoff contract. Verify child-hook inheritance with synthetic client tests; validating the parent request does not prove child enforcement. |
| Delegate to arbitrary agents, override the delegated model, or use background delegation | Blocked | Not part of the constrained delegation grant. |
| Load an allowlisted Fabric skill | Conditional | Exact name in `FABRIC_SKILLS`; skill must be installed. Follow-up tools remain independently gated, and external reference files still require approval. |
<<<<<<< HEAD
| Load a bundled privacy-fabric-* skill | Allowed | Six exact bare or fabric-project-toolkit-qualified names; self-contained offline authoring guidance, not an execution grant. No separate upstream bundle required. |
| Incorporate upstream engineering expertise | Conditional | Curated, pinned adaptations with MIT attribution; no automatic updates, root instructions, executable helpers or upstream MCP registrations imported. Existing nine agents retained. |
| Prepare a future Osmos analysis handoff | Conditional | Offline library validates task-scoped capacity-consent records and projects synthetic operational status. This is not a trusted approval UI or live service integration. |
| Start Osmos from this plugin, even with capacity consent | Blocked | No approved transport or execution tool. Library dispatch always fails with OSMOS_LIVE_DISABLED. Consent is necessary for future runs but cannot enable this implementation. |
| Return Osmos rows, counts, summaries, messages, raw errors or arbitrary URLs | Blocked by design | Offline status projection emits only validated IDs, fixed status and timestamps. The user reviews results in Fabric; no live response path has been verified. |
=======
>>>>>>> cea605b57bfc6cd9a2bd0f37daab7c189851586a
| Fetch public Microsoft documentation, including while using a Fabric skill | Conditional | `web_fetch` HTTPS on `learn.microsoft.com`, `docs.microsoft.com`, or `code.visualstudio.com`; no credentials/query/fragment. Never put business values in URLs. Initial URL check only; redirects are not constrained by the hook. |
| Invoke unlisted skills, browser automation, general web search/fetch, IDE diagnostics, or semantic search tools | Blocked | The documentation/skill grants are narrow, not general tool access. |
| Obtain a query/script for sampling business rows | Allowed | Guidance only: unexecuted read-only template from permitted schema knowledge, or explicitly marked placeholders. User runs and analyzes it in their authorized environment. |
| Ask the user to paste business-row query output | Blocked by guidance | Never request a copy; ask only for non-sensitive observations or technical conclusions. User messages are not hook-filtered. |
| Ask the user a question through the supported `ask_user` payload | Conditional | This engine accepts `question`, optional `choices`, and optional Boolean `allow_freeform`; other payload shapes are denied. |
| Use the session operational SQL tool (`sql`) | Blocked | Distinct from the narrowly scoped `session_store_sql` history path. |
| Use an unknown tool, namespace alias, or new argument | Blocked | Only known bare tool names and their exact `functions.` forms are recognized; supported arguments remain validated. |
| Process data locally by a person or another application | Not covered | The plugin controls Copilot tool calls, not every local/Fabric operation. |
| Use a Foundry-hosted model as the inference destination | Not covered | Routing is client configuration; the plugin neither configures nor verifies it and does not automatically relax policy. |
| Prevent fallback or secondary inference outside an approved BAA boundary | Not covered | Requires verified routing and complementary endpoint/network controls. |

## Setup, failure behavior, and administration

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Initialize a new project from a human terminal | Allowed | Creates project-local policy and advisory configuration; does not install plugins or change personal authentication/settings. |
| Initialize over an existing `.copilot-privacy` directory | Blocked | Non-destructive collision check; existing policy is not overwritten. |
| Use an existing valid policy after upgrading to root trust | Allowed | Internal digest entries no longer gate access. |
| Run protected tools without a policy at the exact current directory | Blocked | No parent-policy discovery and no automatic project opt-out. |
| Use malformed policy, duplicate JSON keys, invalid digests, unknown fields, or invalid task entries | Blocked | Policy validation precedes tool decisions. Legacy internal entries must still be structurally valid. |
| Send malformed, oversized, or invalidly encoded hook input | Blocked | Fixed denial output; input is not echoed. |
| Encounter a missing engine/interpreter, engine crash, or internal wrapper deadline | Blocked | When the wrapper runs and returns within the host deadline, it returns a fixed denial. |
| Ask why an unscoped history query was denied | Allowed | Fixed history-scope guidance is returned; raw query/project values are not echoed. |
| Prove live enforcement using preflight alone | Not covered | Preflight checks static configuration and reports runtime as unverified. |
| Continue safely after a host-level hook timeout, unloaded hook, or disabled plugin | Not covered | Host timeout behavior can fall through to normal permissions. |
| Uninstall the user-installed plugin | Allowed | User terminal operation removes its hooks and agents for that CLI user across projects; start a fresh session. |
| Remove only `.copilot-privacy` to disable the guard | Blocked | This does not unload hooks; subsequent protected calls lack a valid policy. |
| Disable the plugin for only one project | Blocked | No project-specific opt-out mechanism is implemented. |
| Prevent the machine owner from uninstalling or bypassing the plugin | Not covered | A user-installed plugin is not administrator-enforced isolation. |
| Use administrator policy hooks or an admin/repo-owner break-glass exception | Not covered | Discussed architecture, not implemented deployment or exception capability in this plugin. |
| Automatically audit all decisions without retaining sensitive payloads | Not covered | The baseline does not provide persistent decision/denial counting. |

## Context paths outside the hook

| Use case | Decision | Conditions and limits |
| --- | --- | --- |
| Paste business data into a prompt or attach it manually | Not covered | Not screened by the tool hook. |
| Load automatic instructions, MCP resources, or another plugin's startup context | Not covered | Content can arrive before a protected tool call. |
| Use VS Code inline suggestions, chat attachments, editor selections, or open buffers | Not covered | CLI hooks do not intercept VS Code. |
| Use the generated conservative VS Code configuration | Not covered | Advisory settings reduce enabled features; they do not prove content isolation. |
| Use cloud agents, Linux/macOS, or another assistant harness | Not covered | Not verified enforcement targets for this Windows baseline. |
| Establish BAA coverage, retention guarantees, telemetry isolation, or data residency | Not covered | Requires service/contract review and end-to-end technical verification. |

## Evidence and related documentation

These decisions are derived from the current policy and wrapper, not from an
assumption that a live client invokes every hook. Synthetic tests cover
representative allowed/denied operations, history isolation, malformed inputs,
filesystem restrictions, task output suppression, and the Windows wrapper.
Not every row is a separately automated end-to-end test.

- [Policy engine](tools/privacy_guard.py)
- [Windows wrapper](hooks/Invoke-PrivacyGuard.ps1)
- [Setup and preflight](tools/project_setup.py)
- [Policy tests](tests/test_privacy_guard.py)
- [Setup and Windows-hook tests](tests/test_project_setup.py)
- [Installation and operation](README.md)
- [Project goals](PROJECT-GOALS.md)
- [Risk overview](https://softcraftsman.github.io/fabric-project-toolkit/risk-overview.html)
