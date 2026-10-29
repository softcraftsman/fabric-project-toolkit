---
name: privacy-fabric-integration
description: "Draft local Fabric pipeline, Dataflow M, KQL, Eventstream, event-schema, application connectivity, and deployment configuration artifacts. Use for offline integration authoring and promotion planning without data previews, live connections, or service mutations."
---

# Offline workload integration

Follow project AGENTS.md and the active privacy hook. Respect denials without
alternate-tool or identity workarounds. Never execute business-row queries or
request business-data output. This self-contained skill grants no live access.

## Choose the deliverable

- Pipeline: explicit dependencies, activity input/output contracts, parameters,
  timeout/retry behavior, environment bindings, and restart semantics.
- Dataflow: local M and destination/connection placeholders. Validate logic
  using synthetic fixtures where an approved local runner exists. Preview,
  executeQuery, refresh, credentials, and getDefinition are not authorized.
- Eventhouse: draft KQL functions, table schemas, mappings, and policies.
  Do not ingest, query, export, or run management commands against live systems.
- Eventstream/event schema: explicit event contracts, source/destination
  placeholders, routing, serialization, and evolution policy. No payload reads.
- Application: parameterized queries, secure connection configuration,
  bounded retries, and proper connection disposal. Use mocks/fictional data,
  not current Azure credentials, for local tests. Never start a live-connected
  backend or assume an environment file is safe to read.
- Deployment: local parameter/configuration artifacts and a user-operated
  promotion plan. Do not configure Git synchronization, permissions, connections,
  capacity, deployment stages, or schedules.

## Review

Read permitted local definitions and verify API/format details against approved
documentation. Preserve logical IDs, binding contracts, variable types, and
environment separation. Do not fabricate a definition from an unknown endpoint.

Distinguish semantic validation from hosted compatibility. Include synthetic
contract tests and explicit manual readback/rollback instructions, but do not
claim that a script or dry run changed any service.

Externalized credentials remain outside source and logs. A runtime token can
authorize data access but does not authorize exposing results to GHCP.
Do not fall back from blocked MCP tools to CLI, ODBC, XMLA, REST, or helpers.

Adapted from the reviewed Microsoft Fabric Skills revision and sources listed
in THIRD-PARTY-NOTICES.md. Deployment and consumption procedures are excluded.
