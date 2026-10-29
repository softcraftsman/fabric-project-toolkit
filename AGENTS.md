# Toolkit development guidance

This repository develops the privacy plugin; it is not a restricted target
project. It contains infrastructure, not BAA-regulated customer data, and is
not intended to hold such data. Treat its source, documentation, synthetic
fixtures, diagnostics, and project history as engineering artifacts rather
than business-row data.

The deployable instructions are in `templates\AGENTS.md`. Do not install this
development guidance into target projects.

## Engineering permissions

- Use the engineering tools needed for the requested work: source inspection,
  public documentation, MCP tool-contract discovery, local commands, synthetic
  tests, and Git inspection. Target-project wrapper and tool-allowlist rules
  are implementation requirements, not restrictions imposed by this document
  on toolkit development.
- Edit the policy engine, hooks, manifests, agent profiles, templates, and tests
  when the requested change requires it. Do not weaken unrelated controls or
  remove the Fabric agents.
- These instructions do not override active harness permissions, organization
  policies, or hook denials. Never disable or bypass an active control to
  complete a task.
- Do not install into other projects, change personal configuration, deploy
  resources, or change permissions without the user's authorization.

## Infrastructure-only scope

- Develop and test with fictional fixtures and isolated temporary projects.
  Do not retrieve business rows or request business-data output from the user.
- Inspect tool schemas and documentation and validate connectors with synthetic
  harnesses. Live-service access requires user authorization and must not bring
  customer business data into this infrastructure repository or model context.
- Keep secrets and business data out of source, logs, test output, and model
  context. Broader development tooling is not broader business-data access.

## Implementation and verification

- Keep target-project instructions in `templates\AGENTS.md` restrictive and
  consistent with the implemented guard. The installer must preserve existing
  target instructions and require review for changed marked guidance.
- Default-deny unknown tools/actions and validate arguments narrowly. Review
  both output exposure and side effects before expanding permissions.
- Add focused synthetic regression tests for changed behavior. Use
  `python -I -m unittest discover -s tests -v` and `git --no-pager diff --check`
  for final validation; do not use customer environments as test fixtures.
- Distinguish unit tests, real MCP protocol checks, static preflight, and
  actual client-hook enforcement. State unverified boundaries plainly.
- Do not claim BAA compliance, model-routing assurance, response redaction,
  sandboxing, or runtime enforcement that has not been established.
