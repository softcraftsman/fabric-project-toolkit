---
name: privacy-fabric-osmos
description: "Plan an opt-in Fabric-side Osmos query or analysis handoff without returning business results to GitHub Copilot. Use when analysis must stay inside the approved Fabric boundary. Capacity consent is required; live dispatch is currently disabled."
---

# Fabric-side analysis boundary

Follow project AGENTS.md and the active privacy hook. Respect denials without
alternate-tool or identity workarounds. This self-contained skill is a planning
and integration contract, not authority to call Osmos or its upstream helpers.

## Availability

The local tools/osmos_boundary.py module implements synthetic request/consent
validation and a strict operational-status projection. It has no network
transport; dispatch always fails closed with OSMOS_LIVE_DISABLED. Say clearly
that no query or remote task was executed. Do not ask for live credentials.

## Intended workflow once verified and enabled

1. Confirm that the organization approves the specific Fabric deployment and
   service boundary. A product name alone does not establish contractual coverage.
2. Prepare one task using permitted requirements/schema, not business-row
   literals. Scope the workspace, sources, destinations, and operation explicitly.
   The Spark default lakehouse alone is not a scope boundary.
3. Ask the user to approve this exact task, warning that it consumes additional
   Fabric capacity. Do not invent prices, claim a budget cap, or treat a prior
   task's consent as authorization. Changed scope/instructions need new consent.
4. Default to read-only analysis. Write, delete, publish, and permission changes
   need a separate future reviewed capability, not implicit analysis consent.
5. Keep analysis, results, notebooks, messages, query text, and raw errors in
   Fabric. The user reviews them there. Do not download them into the project.
6. A trusted local adapter, before model exposure, may return only validated
   task/operation IDs, a fixed status enum, and validated timestamps. A Fabric
   task link may be added only through a separately verified URL constructor.
   Counts, analytical summaries, assistant messages, logs, arbitrary URLs,
   service runDetails, and error text must never pass through.
7. Interactive service questions are viewed and answered in Fabric; do not
   poll/relay a message stream or use a model to decide which text is safe.

Instructions asking the remote model not to return data are defense in depth,
not the response boundary. Fail closed on malformed status. Consent validation
is a local contract, not proof that a human actually approved a model-authored
record. Before live enablement, implement a trusted human approval path,
verify actual API/auth/URL contracts, and test that responses, exceptions,
logs, retries, and child calls cannot expose business information.

For now, return an unexecuted plan and the unavailable-integration limitation.
Do not route an already denied lookup through Osmos to bypass the denial.

Adapted from Project Osmos at the revision listed in THIRD-PARTY-NOTICES.md.
Upstream message-relay, count-reporting, and execution helpers are not imported.
