# Fabric project toolkit with privacy guardrails

A reusable, Windows-first GitHub Copilot CLI plugin combining targeted Fabric
solution-building agents with controls to reduce accidental business-data
disclosure. The package retains its installation name, `fabric-project-toolkit`,
and its existing agent roles. The [project goals](PROJECT-GOALS.md) define the
intended direction.

See the [use-case and access-decision inventory](USE-CASES.md) for what is
allowed, conditional, blocked, or outside this plugin's coverage.

**This is a cooperative development guardrail, not a BAA compliance
certification, data-loss-prevention product, or execution sandbox.** Do not
open a business-data workspace in Copilot to test it.

## Fabric solution-building agents

Start a fresh CLI session and use `/agent` to select the role needed for a task.
Installing the plugin does not automatically launch a fleet.

| Agent | Responsibility |
| --- | --- |
| delivery-lead | Scope, dependencies, ownership, and integrated delivery |
| solution-architect | Requirements, tradeoffs, contracts, and architecture |
| data-pipeline-engineer | Ingestion, Spark, identity, incremental processing, and recovery |
| fabric-operator | Authorized deployment, execution, monitoring, and recovery |
| semantic-model-engineer | Gold contracts, semantic models, DAX, and report bindings |
| application-ai-engineer | Applications, APIs, and grounded AI integrations |
| quality-engineer | Regression, replay, failure injection, and acceptance evidence |
| independent-reviewer | Read-only correctness and risk review |
| notebook-enablement-author | Notebook organization, documentation, and teaching material |

Privacy controls complement these agents rather than replacing them. Selecting
a role does not authorize business-data access or bypass tool restrictions.
The baseline approves only the narrow Fabric metadata tools described below,
not live business-data queries. Synchronous delegation
to the bundled Fabric agents is supported with the shared safety contract;
child-hook enforcement must be verified in the target client.
Profiles inherit the configured model rather than pinning one. Referenced skills
and other MCP servers remain separate dependencies, not approval grants. The
Microsoft Fabric MCP server is registered by this plugin with a pinned package
and a restricted tool list.

## What the baseline does

- Denies unreviewed tools and arbitrary shell commands on the native CLI
  pre-tool hook path.
- Trusts ordinary files in the project root and its subdirectories without
  per-file entries or SHA-256 checks. Project control files are readable but
  remain protected against edits.
- Allows project directory listings, glob discovery and directory searches,
  after checking the search tree for filesystem aliases and special files.
- Allows read-only local history searches scoped to the current project,
  and read-only Git status/diff/log commands.
- Supports missing project directories through a constrained `mkdir` wrapper,
  Microsoft documentation fetches, and the named Fabric skill allowlist.
- Exposes 13 reviewed Microsoft Fabric MCP tools: offline documentation and
  live workspace/item/capacity discovery plus OneLake namespace/table-name
  listings. Server-side tool restriction and hook argument checks both apply.
- Requires individual human approval and matching SHA-256 digests only for
  files outside the project root, including before external edits.
- Runs explicitly reviewed development tasks through a wrapper. Synthetic-only
  test tasks can return bounded diagnostics; other tasks remain status-only.
- Creates project-local policy and a conservative VS Code profile without
  overwriting existing project configuration or changing authentication.
- Reports static configuration checks separately from unverified runtime
  protection.

Other MCP tools, live-data queries, cross-project/cloud history, arbitrary diagnostics,
unlisted skills/agents, browser tools, and unrestricted shell execution have no baseline
approval. Metadata, schemas, identifiers, aggregates, and notebook outputs are
not automatically safe. Only the specific metadata operations below are
approved; other categories need a separately reviewed extension.

## Requirements

Use Python 3.12 or later, Git, and PowerShell 7 (`pwsh`) on Windows. The plugin uses
the Python standard library. The bundled MCP configuration additionally requires
Node.js 22+ and `npx` on the client's PATH. On first startup, `npx` downloads the
pinned Microsoft package; updates are not implicitly taken from `latest`.
Use a Copilot CLI version supporting plugin command hooks and check the
synthetic protocol and fresh-session behavior after client upgrades.

## Add to a new project (checklist)

1. **Install from GitHub:** `copilot plugin install softcraftsman/fabric-project-toolkit`.
2. **Get the setup utilities and initialize the project** from a human terminal,
   following [Set up a project](#set-up-a-project) below:
   `python -I "$ToolkitRoot\tools\project_setup.py" init --project "$ProjectRoot"`.
   This creates `<project>\.copilot-privacy\` containing `policy.json`,
   `advisory-settings.json`, and `guidance.txt`. It refuses to run if that folder
   already exists and changes nothing else. Commit `.copilot-privacy\policy.json`
   only after review; it lists file names and digests, never contents.
3. **Keep the project tree curated.** Internal files need no registration.
   Approve only external files the agent needs (see below).
4. **Run preflight:** `python -I "$ToolkitRoot\tools\project_setup.py" preflight --project "$ProjectRoot"`.
5. **Optional, VS Code:** create a new empty profile (Profiles: Create Profile),
   paste `.copilot-privacy\advisory-settings.json` into its settings JSON, and
   select it for the project window.
6. **Start a fresh CLI session from the project root**, confirm the plugin and
   hook are loaded, and test with synthetic files only.
   Install the [shared agent instructions](#shared-agent-instructions) first so
   bundled and other project agents receive the same fallback guidance.

Keep business data out of the project folder and out of pasted prompts; the
guard cannot see those paths.

View the [risk overview and data-flow diagram](https://softcraftsman.github.io/fabric-project-toolkit/risk-overview.html)
for the risks addressed and not addressed by the plugin.

## Set up a project

Run setup and classification from a **human terminal**, not through the agent.
Keep the plugin directory separate from the target project's working tree.
Install the plugin from
[softcraftsman/fabric-project-toolkit](https://github.com/softcraftsman/fabric-project-toolkit),
then clone the same repository for its human-operated setup utilities. No path
on the author's machine is required; the utilities run locally on each user's
machine.

```powershell
copilot plugin install softcraftsman/fabric-project-toolkit

# Run from the root of the project you want to protect.
$ProjectRoot = (Get-Location).Path
# Keep the setup utilities outside that project.
$ToolkitRoot = Join-Path $HOME 'tools\fabric-project-toolkit'
New-Item -ItemType Directory -Force -Path (Split-Path $ToolkitRoot -Parent) | Out-Null
git clone https://github.com/softcraftsman/fabric-project-toolkit.git "$ToolkitRoot"
python -I "$ToolkitRoot\tools\project_setup.py" init --project "$ProjectRoot"
```

GitHub is the installation and distribution source. Setup and approval still
run locally because they configure and review files in the target project;
`$ProjectRoot` uses your current directory rather than a fixed drive or path.

If you already have a checkout, set `$ToolkitRoot` to that directory instead
of cloning again. Keep the setup checkout and installed plugin on the same
reviewed revision. Access to a private repository requires GitHub authentication
for both Copilot's installer and Git.

Setup starts with an empty external-file/task policy. **The project root and
its subdirectories are trusted automatically** for reads. Policy, hook, plugin,
and other control paths remain protected against edits. Internal files require neither approval
entries nor hashes, even after edits. Keep business data and secrets outside
that tree: an export saved inside it can enter model context.

**Existing projects adopt root trust automatically after updating the plugin.**
Legacy internal file entries may be removed; their digests no longer gate access.
The project policy is still required. Missing policy does not enable access.

For an external file, review it locally to confirm it contains only source code
without embedded business values or secrets, or genuinely synthetic test data.
Use its absolute path; external directory grants are not supported:

```powershell
$ExternalFile = Join-Path $HOME 'shared-source\example.py'
python -I "$ToolkitRoot\tools\privacy_guard.py" approve --project "$ProjectRoot" --path "$ExternalFile" --category source --reviewed
python -I "$ToolkitRoot\tools\project_setup.py" preflight --project "$ProjectRoot"
```

`--reviewed` is a human attestation, not a content scanner or proof of safety.
External-file digests detect changes after review, not whether the original
review was correct. External reads, searches, and edits require a matching
digest; reapprove after changes, including agent edits. Internal approval calls
return `PROJECT_ROOT_TRUSTED` without adding entries or hashing the file.
Directory listings, `glob` discovery, and `rg`/`grep` directory searches are
allowed inside the project, including default-current-directory searches and
ordinary glob/type filters. Discovery accepts `/` or `\` path separators.
External directories are not granted access: external content searches still
require approved individual files. Symlinks, junctions, hard-linked files,
special files, and path traversal remain blocked. A directory search/listing is
denied if its entire possible input tree contains one of these, or exceeds
50,000 entries; narrow the search to an ordinary subdirectory in that case.
Policy, hook, and plugin implementation files are not ordinary editable targets.
The assistant must not approve its own changes or broaden the policy.

Start a fresh CLI session from the exact target project root. Confirm the
plugin is enabled and its hooks are loaded using the client's plugin and
environment views. A successful installation or static preflight does not prove
the runtime hook is active. First exercise approved and denied operations using
synthetic files only. Do not use allow-all modes or disable hooks.

Update the installed GitHub plugin after reviewing upstream changes, update
the setup checkout to the corresponding revision, and start a fresh session:

```powershell
copilot plugin update fabric-project-toolkit
```

For plugin development only, temporary CLI loading from your checkout is also
available instead of using the installed copy:

```powershell
copilot --plugin-dir "$ToolkitRoot"
```

## Shared agent instructions

[templates/AGENTS.md](templates/AGENTS.md) defines target-project guidance for the bundled Fabric
roles and other agents, including the default fallback when a data query is
blocked: respect the denial, do not bypass it, and offer only an explicitly
unexecuted read-only SQL/DAX template using permitted schema knowledge.

For **new and existing target projects**, run this from a human terminal after
setting `$ToolkitRoot` and `$ProjectRoot` as above:

```powershell
python -I "$ToolkitRoot\tools\project_setup.py" instructions --project "$ProjectRoot"
```

This creates root `AGENTS.md`, or appends the shared guidance while preserving
existing bytes. Repeating the command with identical guidance changes nothing.
If the marked guidance was modified or comes from an older version, the command
requests human review rather than overwriting it. Review and commit the file,
then start a fresh agent session. `init` remains unchanged and does not install
instructions implicitly.

The toolkit's own root [AGENTS.md](AGENTS.md) permits broader plugin development
and is never the installer source. The restrictive template is installed as
root `AGENTS.md` in the target project, the default for clients/agents that load it;
installing the plugin alone does not install these instructions into a target
repository. Review nested instructions and custom agent prompts for conflicts,
and include relevant rules in authorized handoffs to agents that do not inherit
them. Instructions are behavioral guidance, not guaranteed enforcement across
every agent or harness; the policy hook remains the tool-access gate.

Uninstalling the plugin does not remove shared instructions appended to
`AGENTS.md`. A human can remove the marked toolkit section while retaining
the project's other instructions.

## Repository status and current-project history

Git status and full diff/log output are allowed through the PowerShell tool:

```powershell
git --no-pager status --short
git --no-pager diff --no-ext-diff --no-textconv
git --no-pager diff --cached --no-ext-diff --no-textconv
git --no-pager log -p
```

Common read-only display flags, revision ranges and project-relative pathspecs
are supported, not arbitrary options or shell chaining. Git mutations and
other shell commands still need a reviewed task.
For repositories with custom Git helpers, prefer
`git -c core.fsmonitor=false --no-pager status --short` to disable the fsmonitor
helper for the status operation. Git configuration remains trusted local code.

The `session_store_sql` tool is allowed with **`source: "local"`** for sessions
in the exact current project directory. There is no plugin row cap, mandatory
sort order, or fixed projection. Search summaries and transcripts, filter by
time or session ID, and use aggregates, grouping, wildcard columns, and optional
ordering/pagination. The history tool itself can impose its own result limits.

Keep the exact `cwd` equality as a top-level `AND` condition. Replace
`<project-root>` with the current project root, escaping any apostrophe as `''`.
For alternatives, use `AND (condition OR condition)` so they cannot widen the
project scope. Examples:

```sql
SELECT id, summary, updated_at FROM sessions
WHERE cwd = '<project-root>'
ORDER BY updated_at DESC LIMIT 20
```

```sql
SELECT t.session_id, t.user_message, t.assistant_response FROM turns AS t
JOIN sessions AS s ON t.session_id = s.id
WHERE s.cwd = '<project-root>'
AND (t.user_message LIKE '%silver%' OR t.assistant_response LIKE '%silver%')
ORDER BY t.timestamp DESC LIMIT 50
```

Query `sessions` directly, optionally with an alias, or join `turns`,
`checkpoints`, `session_files`, or `session_refs` to `sessions` on
`<history-alias>.session_id = <sessions-alias>.id`. Aliases need not be `t`/`s`.
Supported expressions include common text, date/time, null-handling, and
aggregate SQLite functions. The engine validates SQL against an empty in-memory
schema; it does not read your history during the policy check.

Unscoped/cross-project reads, cloud history, subqueries, unions, window
functions, arbitrary SQL functions, and database writes remain blocked.
This is a scoped SELECT subset, not unrestricted SQL. Scope is the exact
project directory, not every clone or worktree with the same Git remote.
History absent from the local store is not retrieved.

**Current-project history is trusted content, not a sanitized result.** It may
contain text or tool results from previous work, including material originally
read outside the project. Do not rely on the project filter to remove business
data from old transcripts. Keep such history out of non-approved model context.

## Uninstall

1. Exit Copilot CLI, then run this from a regular human terminal:

   ```powershell
   copilot plugin uninstall fabric-project-toolkit
   ```

2. Optionally delete the target project's `.copilot-privacy` folder after
   preserving any approval policy you need. If it is tracked in Git, review
   and commit its removal through your normal process.
3. If you imported the VS Code advisory profile, switch to another profile
   and optionally delete the imported profile.
4. Start a fresh Copilot CLI session. Use `copilot plugin list` to confirm
   the plugin is no longer installed, and `/env` to inspect loaded hooks.

**Uninstalling removes this plugin's agents and hooks for your CLI user across
all projects, not just the current project.** Deleting `.copilot-privacy` alone
does not remove the hooks; the installed guard remains without an approval
policy. The baseline has no project-specific opt-out.

If you loaded the plugin using `--plugin-dir`, omit that option when restarting;
uninstalling an installed copy does not stop explicit directory loading.
No manual hook-file deletion is needed for the baseline installation.
Separately deployed administrator policy hooks require administrator removal
and are not removed by uninstalling this plugin.

Removing the guard removes its protections. Keep business data out of Copilot
context and use your organization's approved controls before resuming work.

## Directories, documentation, and Fabric delegation

Create missing nested directories from the project root using the installed
engine, rather than unrestricted PowerShell:

```powershell
python -I '<installed-plugin-root>\tools\privacy_guard.py' mkdir --path 'src\pipelines\silver'
```

Only project-relative ordinary directories are supported; control directories,
external paths and link escapes remain denied. Then use `create` for files.

`web_fetch` permits HTTPS documentation URLs on `learn.microsoft.com`,
`docs.microsoft.com`, and `code.visualstudio.com`, without credentials, query
strings or fragments. Use public documentation URLs only, never business-data
values in URLs. This checks the initial URL, not the fetcher's redirect chain;
it is not a network-isolation control. General web search/browsing remains
blocked.

The `skill` tool permits the named Fabric workload/migration skills listed
in `FABRIC_SKILLS` in `tools\privacy_guard.py` (including `spark-cli`,
`pipeline-migration`, and `semantic-model-authoring`). Skills must be installed
separately. Loading instructions does not grant their tools extra permissions:
documentation fetches are allowed; live MCP queries and unreviewed commands
remain blocked. External reference files still need external-file approval.

The `task` tool permits synchronous delegation to the nine
`fabric-project-toolkit:<role>` agents. Include the exact contract in
[target-project guidance](templates/AGENTS.md) in each prompt. Background delegation, arbitrary agent
types, and model overrides are not granted. Shared guidance is also included
in every bundled agent profile. **Verify child tool calls invoke the same hook
using synthetic tests in your client**; the hook cannot establish inheritance
merely by checking the parent task request.

For sample business rows, the agent must provide an **unexecuted read-only**
query or script for you to run and analyze. It may ask for non-sensitive
observations/conclusions, not business-data output, and must not run the query.

## Fabric metadata MCP policy

The plugin registers **Microsoft Fabric MCP Server (local)** as
`fabric-metadata` using `@microsoft/fabric-mcp@1.6.0`. It covers the first useful
engineering inventory without adding overlapping remote connectors. The
configuration is in [mcp-config.json](mcp-config.json); installation does not
edit your personal MCP configuration or authenticate to Fabric.

The server starts with `--read-only`, `--disable-proxy-tools`, and repeated
`--tool` switches naming only the following tools. The client's `tools` list
matches those switches. The hook independently rejects unknown actions and
unreviewed arguments; loading a skill never broadens this list.

| Allowed tools | Scope |
| --- | --- |
| `docs_list-item-types`, `docs_platform-api-spec` | Offline public API documentation; no arguments |
| `docs_item-api-spec`, `docs_item-definitions`, `docs_api-examples` | Offline bundled documentation for an `item-type`, not a live item's definition |
| `docs_best-practices` | Offline documentation for a bounded topic |
| `core_list-workspaces` | Accessible workspace inventory; optional role filter and continuation token |
| `core_list-items` | Item inventory within a workspace UUID; optional type, folder UUID, recursion and continuation token |
| `core_get-item` | Generic item metadata for workspace/item UUIDs, not contents or definitions |
| `core_list-capacities`, `core_get-capacity` | Accessible capacity inventory or one capacity UUID |
| `onelake_list-table-namespaces` | Schema/namespace names for workspace/item UUIDs |
| `onelake_list-tables` | Table-name inventory for workspace/item UUIDs and a simple `namespace` identifier |

Use the exact hyphenated argument names returned by `tools/list`. UUIDs must
be nonzero and in dashed form. Friendly-name aliases (`workspace`, `item`,
`schema`), endpoint/authentication overrides, arbitrary selectors and unknown
arguments are not accepted. The workspace-specific-endpoint preference may
only be omitted, null or false. Other MCP server identities remain denied.
The supported hook identity is `fabric-metadata-<tool>`; an unrecognized client
alias fails closed rather than authorizing tools by suffix.

**Still blocked:** SQL/DAX/KQL/M execution (including aggregates), row previews,
value search, full live table/item/model definitions, notebook outputs, file
listing/download/upload, jobs, refreshes, mutations, permissions, shortcuts,
security/settings tools, operation results and arbitrary catalog searches.
This intentionally does **not yet enable column-level schema inspection**.
OneLake's full table tool returns an unfiltered definition and raw response;
Fabric IQ schema/report tools can include business literals, filters, custom
instructions and verified answers. Read-only labels are insufficient approval.
Warehouse, Eventhouse, Fabric IQ, Power BI Authoring, DataFactory and other
MCP servers are not registered or approved by this change.

**Metadata is not redacted.** Allowed inventory can include names, descriptions,
tags, identifiers, endpoints and continuation information; OneLake listings
also return raw metadata responses. Service errors are not output-filtered.
Only connect to an environment where those fields are approved technical
metadata, not business values or secrets. Use a least-privilege identity:
the local server uses its configured host credentials, which may differ from
the person using Copilot. Workspace discovery covers the identity's accessible
workspaces, not a project-specific workspace allowlist. Local hosting does not
keep tool results out of the selected model.

After updating the plugin, start a fresh CLI session, confirm `fabric-metadata`
and the privacy hook are loaded, and first try the offline `docs_list-item-types`
tool. Verify allowed and denied synthetic calls before connecting live
credentials. Normal client permissions still apply. Preflight checks the
packaged configuration, not Node/npm availability, active server identity,
actual client dispatch, or authentication. Older installed AGENTS.md guidance
requires a reviewed manual merge; the instruction installer will not overwrite it.

The package's actual MCP catalog was inspected: **13 of 62 tools are exposed;
49 remain unexposed**, and unknown tools default-deny. Protocol checks exercised
offline documentation and rejection of unexposed download/query/create tools,
without customer credentials or business queries. Re-review tool contracts and
output behavior before changing the pinned version.

References: [Microsoft Fabric MCP repository](https://github.com/microsoft/mcp/tree/main/servers/Fabric.Mcp.Server),
[Core tools](https://github.com/microsoft/mcp/tree/main/tools/Fabric.Mcp.Tools.Core),
[OneLake tools](https://github.com/microsoft/mcp/tree/main/tools/Fabric.Mcp.Tools.OneLake),
and [Fabric IQ tool contract](https://learn.microsoft.com/en-us/fabric/iq/connectors/fabric-iq-mcp#available-tools).

## Reviewed development tasks

A human may add fixed tasks to `.copilot-privacy\policy.json`. For example:

```json
{
  "version": 1,
  "files": [],
  "tasks": {
    "test": {
      "argv": ["python", "-I", "-m", "unittest", "discover", "-s", "tests"],
      "reviewed": true,
      "synthetic_only": true,
      "output": "diagnostics"
    }
  }
}
```

The `files` list is only needed for external file approvals; leave it empty
when all required files are inside the project. Review the task's
executable, imports, configuration, fixtures, and side effects before approval.
Use an absolute executable path when interpreter identity matters.

From the project root, the hook recognizes only its installed wrapper's exact
PowerShell command, synchronously:

```powershell
python -I '<installed-plugin-root>\tools\privacy_guard.py' run --task test
```

Replace `<installed-plugin-root>` with the actual installed plugin directory
on that machine (the directory containing `plugin.json`). For an installed
plugin, use its cached path, not `$ToolkitRoot`, which is the separate setup
checkout. When using `--plugin-dir`, use that directory instead.
For local tests with synthetic fixtures and no live-data credentials, set
`"synthetic_only": true` and `"output": "diagnostics"` to return captured
stdout/stderr (including assertions and tracebacks) in the result's `output`
field. Output is bounded to 1 MiB and execution to 60 seconds. This allows the
agent to diagnose failed local tests rather than guessing from pass/fail.
The synthetic-only flag is a human attestation, not a content detector.
Existing tasks default to `"output": "status"` and keep suppressing output.

**A reviewed task still executes mutable local code with the user's
permissions.** Capturing output does not prevent filesystem writes, network
access, credential use, or data exfiltration by that code. Use only a curated
code-only environment with synthetic fixtures and no live-data credentials.

## VS Code status

The generated profile under `.copilot-privacy` is a conservative fallback:
agent mode, MCP, skills, plugins, and terminal auto-approval are disabled.
Paste its plain-JSON settings into a new VS Code profile and select it for the
target window. Existing workspace settings and personal profiles are not overwritten.

**VS Code is not tool-enforced by this baseline.** The CLI hook is not a
VS Code interceptor. Inline completions, chat attachments, editor selections,
open buffers, and extension-provided context are not screened by these hooks.
Only use VS Code Copilot in a separately curated code-only workspace; importing
the profile is not proof that business data cannot enter context.

## Limits and failure behavior

- CLI hooks can be unloaded, disabled, or modified. Documented hook timeouts
  fall through to normal permissions; this plugin cannot make the host
  universally fail closed.
- Pasted prompts, attachments, automatic instructions, resumed sessions,
  automatic MCP resources, and other non-tool context paths are not intercepted.
  Keep sensitive information out of those paths before starting Copilot.
- Project-root trust does not inspect content or detect internal-file drift.
  Business data placed inside the project is not blocked by classification.
  External hash checks reduce accidental drift but do not prevent concurrent
  changes between checking and reading. This is not a defense against hostile
  local processes.
- Other installed plugins or integrations may load context before any tool
  invocation. Use a clean, reviewed client configuration.
- Policy and profile files, Git-ignore rules, and file exclusions are not
  operating-system access controls. Protection against deliberate bypass
  requires independently managed access and isolation controls.
- Preflight checks static files. It does not certify the active VS Code
  profile, installed extension hosts, model routing, contractual coverage,
  connector identity, or live enforcement.
- Linux, macOS, cloud agents, and other assistant harnesses are not verified
  enforcement targets for this Windows baseline.

## Local validation

Run the synthetic suite from this plugin's root:

```powershell
python -I -m unittest discover -s tests -v
```

The suite uses temporary synthetic projects and does not query customer
services. Plugin installation/discovery and real client interception are
distinct checks; a protocol test is not a live enforcement certification.

Customer-specific Fabric authentication and deployment exceptions from the
initial attempt are intentionally not inherited. The reusable Fabric agents
remain part of the package alongside the privacy-control baseline.

## Platform references

- [CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [CLI hook formats and failure behavior](https://docs.github.com/en/copilot/reference/hooks-reference)
- [VS Code AI settings](https://code.visualstudio.com/docs/agents/reference/ai-settings)
