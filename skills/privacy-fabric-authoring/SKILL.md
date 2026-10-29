---
name: privacy-fabric-authoring
description: "Author local Fabric notebooks, PySpark, Spark SQL, Warehouse T-SQL, SQL database definitions, and Materialized Lake View drafts with synthetic tests. Use for implementation or code review, not live queries, deployment, or job execution."
---

# Local Fabric authoring

Follow project AGENTS.md and the active privacy hook. Respect denials without
alternate-tool or identity workarounds. Use only permitted schema knowledge;
mark unknown identifiers as placeholders. Never execute business-row queries
or request business-data output. This self-contained skill grants no live access.

## Plan and author

1. Read the existing code and approved schema artifacts. Confirm target workload,
   dialect, source/destination contracts, keys, change tracking, and rerun policy.
2. Keep resource IDs, endpoints, paths, and environment settings configurable.
   Use managed identity/approved secret references in generated runtime code;
   never embed credentials or print tokens.
3. Author local files and synthetic tests. A saved local artifact is a completed
   authoring deliverable, not proof of deployment or hosted correctness.

## Notebooks and Spark

- For ipynb code cells use empty outputs and null execution_count. Remove
  execution outputs from deliverables; do not retrieve a live notebook to do so.
- Specify schema-enabled lakehouses and explicit schema-qualified tables.
  Keep library/environment setup separate from transformation logic.
- Keep distributed transformations in Spark; avoid unbounded driver collection.
  Do not display, print, or log business rows in generated validation code.
- Use explicit schemas, stable source keys, and deterministic deduplication
  rules. Preserve rejected records in authorized runtime quarantine storage,
  not in the local repository or conversation.
- Incremental logic needs late-arrival handling, a restart-safe watermark,
  ownership/checkpoint evidence, and idempotent writes. Partition overwrite
  must not erase unrelated partitions; MERGE needs a unique source per key.
- Delta format, partitioning, compaction, and MLVs are design choices to justify
  from scale and access patterns, not universal performance guarantees.
- MLVs require schema-enabled lakehouses. Verify current Fabric-specific syntax
  using permitted documentation tools before generating a definition; do not
  invent a scheduling API or run a discovery query to fill missing schema.

## Warehouse and SQL database

Choose the correct endpoint dialect before writing DDL. Warehouse, Lakehouse
SQL analytics endpoints, and Fabric SQL database have different write surfaces;
do not assume Lakehouse SQL endpoints accept table DDL/DML. Parameterize query
values. Design transaction, schema-evolution, and recovery behavior explicitly.
Do not run schema SELECTs, counts, query-insights queries, or sample previews.

## Validation and handoff

Use reviewed synthetic tasks for null keys, duplicates, replay, late arrivals,
schema drift, and partial failure. Provide unexecuted read-only validation
queries for the user to run and analyze; request only non-sensitive findings.
Include counting semantics and null treatment. Report local tests separately
from unverified hosted behavior. Do not turn a blocked MCP call into sqlcmd,
Livy, REST, or another agent call.

Adapted from the reviewed Microsoft Fabric Skills revision and sources listed
in THIRD-PARTY-NOTICES.md. No upstream helper scripts are required.
