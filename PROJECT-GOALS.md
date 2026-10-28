# Project goals

## Purpose and scope

Build a reusable plugin that projects can adopt to reduce accidental disclosure
of business data to GitHub Copilot models outside the approved Business
Associate Agreement (BAA) boundary.

The initial scope covers GitHub Copilot CLI and VS Code Copilot. Protection must
act before restricted information enters model context, not merely redact
answers after disclosure.

The plugin also provides targeted agents for building Microsoft Fabric
solutions. Privacy controls complement these agents; they do not replace them.
Retain the existing Fabric solution-building roles and apply the data boundary
consistently to their tools, workflows, and any delegation.

The agreed baseline allows source code and synthetic test data into context.
Business-row values and secrets are prohibited. Other information requires
explicit classification and approval before disclosure. Source code is not
automatically safe if it contains embedded business values or secrets.

Project-root trust is the file-access boundary: ordinary files inside the root
and its subdirectories require neither inventory entries nor SHA-256 checks.
Only external files require individual human approval and matching digests,
including before edits; changes require reapproval. This applies automatically
to existing and new projects. Protected control paths and filesystem-alias
restrictions remain. The operator must keep business data outside the trusted
tree; root trust is not content classification or proof of BAA coverage.

These are target goals, not a statement that the current plugin implements
all these protections. The initial restricted-development attempt informs
the design but does not define the reusable plugin's authoritative policy.

## Goals and acceptance criteria

In the Basis column, **Agreed scope** identifies confirmed requirements,
**Existing** identifies an approach present in the initial attempt, and
**New** identifies a recommended extension for review. Existing behavior is
not automatically approved for the reusable plugin.

| # | Goal | Acceptance criterion | Basis |
| --- | --- | --- | --- |
| 1 | Define a clear data boundary | Source code and synthetic test data are eligible for context; business rows and secrets are prohibited. Other information requires explicit classification and approval before disclosure. Files containing code are not automatically safe. | Agreed scope |
| 2 | Make adoption reusable and non-destructive | A project can install the plugin and supply a small policy configuration without copying customer-specific scripts. Existing instructions, settings, and personal configurations are preserved; conflicts are reported. | New |
| 3 | Deny unreviewed capabilities by default | Unknown tools, connectors, skills, agents, and newly introduced capabilities remain blocked on supported enforcement paths. Approvals use narrow identities and validated arguments, not blanket server grants. | Existing |
| 4 | Scope file trust to the project root | Ordinary project files need no individual registration or hashes. External files require explicit human approval and SHA-256 verification before reads, searches, or edits. Protected controls and link escapes remain blocked. Unsupported paths are explicitly identified; internal business data is a documented residual risk. | Agreed scope |
| 5 | Preserve practical coding workflows | Developers can edit approved code, lint, format, build, and run synthetic tests through constrained operations. Arbitrary execution is not required for ordinary supported tasks. Executed project code remains a documented risk. | Existing |
| 6 | Support CLI and VS Code explicitly | Each client has its own verified configuration and acceptance tests. A CLI hook never counts as proof of VS Code protection. Features without verified controls are disabled or marked outside the protected workflow. | Agreed scope; extends pilot |
| 7 | Separate local processing from model-visible results | Sensitive processing may run locally or within an approved service boundary, but only classified, approved results return to Copilot. Raw errors, logs, previews, and saved outputs do not become an accidental return channel. | Existing principle; new mechanism |
| 8 | Require deliberate, scoped exceptions | Approval identifies the information category, operation, destination, and scope. Permission to execute a tool does not automatically authorize disclosure of its output. The assistant cannot widen policy simply to finish a task. Exceptions do not authorize business-row values or secrets under the agreed baseline. | Extends existing review process |
| 9 | Verify readiness and expose degraded protection | Preflight checks policy validity, required components, configuration conflicts, and supported client versions. Missing or ineffective controls never produce a misleading protected status; runtime limitations are visible. | Existing; extend runtime verification |
| 10 | Keep evidence without retaining sensitive payloads | Diagnostics record rule IDs, decisions, component versions, and safe reason codes, not business values, credentials, raw tool arguments, or full responses. | Extends existing safe diagnostics |
| 11 | Prove behavior with synthetic end-to-end tests | Tests exercise allowed development work, blocked disclosure paths, malformed inputs, policy changes, hook failures and timeouts, and client upgrades without touching real customer data. | Existing; extend client coverage |
| 12 | Preserve and enable Fabric solution-building agents | Retain the existing targeted agents and their plugin registration. Developers can select the appropriate Fabric role and perform reviewed solution-building workflows within the privacy controls. Agent availability does not grant unrestricted data access, tool use, deployment, or delegation. Removing these agents is not baseline cleanup. | Agreed scope |

## Changes from the initial attempt

The initial allowlist permits file, search, and history tools by name and
grants several Fabric metadata inspections. Those exceptions must not carry
forward automatically under the agreed baseline. Schemas, identifiers,
aggregates, and definitions require classification and approval too.

The pilot disables VS Code agents and plugins. That is a conservative fallback,
not a working VS Code implementation of this plugin. The reusable design must
verify how its controls are delivered and applied on each supported client.

Fabric-specific authentication and connector controls should be optional
integrations, not requirements of the reusable privacy-control core. This
separation does not remove the plugin's Fabric solution-building agents.

## Non-goals and limits

- Certifying BAA compliance or determining contractual coverage.
- Preventing deliberate bypass by a machine owner.
- Providing administrator-grade isolation through a plugin alone.
- Claiming protection for unsupported clients or unverified context paths.

Instructions and cooperative controls are not equivalent to an independently
enforced security boundary. Documentation and readiness reporting must
distinguish verified controls, advisory guidance, and known gaps.

## Baseline implementation

The baseline focuses on the native Windows CLI tool-call path. Its file
tree is trusted without per-file inventory or hashing. Only external files
require explicit human review and matching content digests. Integrations have
no automatic exception. Project-local business data is not screened.

| Area | Baseline scope |
| --- | --- |
| CLI tool access | Project-root file trust, digest-approved external files, and constrained task-wrapper paths; other capabilities default-deny |
| Fabric agents | Retain targeted solution-building roles alongside the guardrails; review capabilities without granting blanket access |
| Content classification | No per-file registration or hashes inside the project; external source/synthetic approvals require digests; protected control paths remain blocked |
| Local development | Reviewed tasks return status without streaming child output; execution is not sandboxed |
| VS Code | Conservative manually selected profile; no claim of equivalent tool interception |
| Readiness | Static configuration and drift checks, not certification of runtime enforcement |
| Exceptions | Other information categories remain blocked pending a separately reviewed extension |

Implementation and operating guidance:

- [Setup, validation, and limitations](README.md)
- [Policy handler and development task wrapper](tools/privacy_guard.py)
- [Project setup and preflight](tools/project_setup.py)
- [Plugin hook configuration](hooks/hooks.json)
- [Policy tests](tests/test_privacy_guard.py)
- [Setup and integration tests](tests/test_project_setup.py)
