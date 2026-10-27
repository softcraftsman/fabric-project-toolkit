# Fabric project toolkit with privacy guardrails

A reusable, Windows-first GitHub Copilot CLI plugin combining targeted Fabric
solution-building agents with controls to reduce accidental business-data
disclosure. The package retains its installation name, `fabric-project-toolkit`,
and its existing agent roles. The [project goals](PROJECT-GOALS.md) define the
intended direction.

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
The baseline does not yet approve live Fabric connectors or delegated agent
execution; workflows needing them require separately reviewed capabilities.
Profiles inherit the configured model rather than pinning one. Referenced skills
and MCP servers are separate dependencies, not bundled approval grants.

## What the baseline does

- Denies unreviewed tools and arbitrary shell commands on the native CLI
  pre-tool hook path.
- Allows supported reads and narrowly scoped searches only for individually
  reviewed source or synthetic files whose SHA-256 digests still match.
- Provides a human-only classification command. A file extension or directory
  name is not evidence that content is safe.
- Runs explicitly reviewed development tasks through a wrapper that returns
  status rather than raw child-process output.
- Creates project-local policy and a conservative VS Code profile without
  overwriting existing project configuration or changing authentication.
- Reports static configuration checks separately from unverified runtime
  protection.

MCP tools, live-data queries, history retrieval, arbitrary diagnostics, skills,
delegation, browser tools, and unrestricted shell execution have no baseline
approval. Metadata, schemas, identifiers, aggregates, and notebook outputs are
not automatically safe. This baseline does not provide an exception mechanism
for those categories: withhold them pending a separately reviewed extension.

## Requirements

Use Python 3.12 or later and PowerShell 7 (`pwsh`) on Windows. The plugin uses
the Python standard library; no dependency installation is needed.
Use a Copilot CLI version supporting plugin command hooks and check the
synthetic protocol and fresh-session behavior after client upgrades.

## Add to a new project (checklist)

1. **Install once per machine:** `copilot plugin install C:\Fabric\fabric-project-toolkit`.
2. **Initialize the project** from a human terminal:
   `python -I C:\Fabric\fabric-project-toolkit\tools\project_setup.py init --project <project root>`.
   This creates `<project>\.copilot-privacy\` containing `policy.json`,
   `advisory.code-profile`, and `guidance.txt`. It refuses to run if that folder
   already exists and changes nothing else. Commit `.copilot-privacy\policy.json`
   only after review; it lists file names and digests, never contents.
3. **Classify files** the agent may read (see below). Unclassified files stay
   blocked.
4. **Run preflight:** `... project_setup.py preflight --project <project root>`.
5. **Optional, VS Code:** manually import `.copilot-privacy\advisory.code-profile`
   (Profiles: Import Profile) and select it for the project window.
6. **Start a fresh CLI session from the project root**, confirm the plugin and
   hook are loaded, and test with synthetic files only.

Keep business data out of the project folder and out of pasted prompts; the
guard cannot see those paths.

An HTML summary of the risks addressed and not addressed is in
[docs\risk-overview.html](docs/risk-overview.html).

## Set up a project

Run setup and classification from a **human terminal**, not through the agent.
Keep the plugin directory separate from the target project's working tree.

```powershell
copilot plugin install C:\Fabric\fabric-project-toolkit
python -I C:\Fabric\fabric-project-toolkit\tools\project_setup.py init --project C:\Projects\Example
```

Setup starts with an empty file/task policy. No files are automatically
approved. Review each file locally to confirm it contains only source code
without embedded business values or secrets, or genuinely synthetic test data:

```powershell
python -I C:\Fabric\fabric-project-toolkit\tools\privacy_guard.py approve --project C:\Projects\Example --path src\example.py --category source --reviewed
python -I C:\Fabric\fabric-project-toolkit\tools\privacy_guard.py approve --project C:\Projects\Example --path tests\test_example.py --category synthetic --reviewed
python -I C:\Fabric\fabric-project-toolkit\tools\project_setup.py preflight --project C:\Projects\Example
```

`--reviewed` is a human attestation, not a content scanner or proof of safety.
Digests detect changes after review, not whether the original review was
correct. Re-review and reapprove changed files before subsequent access.
Policy, hook, and plugin implementation files are not ordinary editable targets.
The assistant must not approve its own changes or broaden the policy.

Start a fresh CLI session from the exact target project root. Confirm the
plugin is enabled and its hooks are loaded using the client's plugin and
environment views. A successful installation or static preflight does not prove
the runtime hook is active. First exercise approved and denied operations using
synthetic files only. Do not use allow-all modes or disable hooks.

Installed directory plugins may be cached; reinstall after changing plugin
files and start a fresh session. Temporary CLI loading is also available:

```powershell
copilot --plugin-dir C:\Fabric\fabric-project-toolkit
```

## Reviewed development tasks

A human may add fixed tasks to `.copilot-privacy\policy.json`. For example:

```json
{
  "version": 1,
  "files": [],
  "tasks": {
    "test": {
      "argv": ["python", "-I", "-m", "unittest", "discover", "-s", "tests"],
      "reviewed": true
    }
  }
}
```

Keep the file inventory populated by the classification command; the empty
inventory above only illustrates the policy structure. Review the task's
executable, imports, configuration, fixtures, and side effects before approval.
Use an absolute executable path when interpreter identity matters.

From the project root, the hook recognizes only its installed wrapper's exact
PowerShell command, synchronously:

```powershell
python -I 'C:\Fabric\fabric-project-toolkit\tools\privacy_guard.py' run --task test
```

For an installed plugin, use the actual cached plugin path in that command,
not the source directory path. The wrapper does not stream test failures or
other child output into model context. Investigate detailed failures locally,
then provide a separately reviewed synthetic reproduction.

**A reviewed task still executes mutable local code with the user's
permissions.** Capturing output does not prevent filesystem writes, network
access, credential use, or data exfiltration by that code. Use only a curated
code-only environment with synthetic fixtures and no live-data credentials.

## VS Code status

The generated profile under `.copilot-privacy` is a conservative fallback:
agent mode, MCP, skills, plugins, and terminal auto-approval are disabled.
Import it manually using VS Code's profile UI and select it for the target
window. Existing workspace settings and personal profiles are not overwritten.

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
- File review and subsequent access are separate operations. Hash checks reduce
  accidental drift but do not prevent concurrent changes between checking and
  reading. Do not use this as a defense against hostile local processes.
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
