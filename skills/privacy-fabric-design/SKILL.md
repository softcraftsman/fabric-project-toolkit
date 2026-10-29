---
name: privacy-fabric-design
description: "Design privacy-aware Fabric data platforms, medallion layers, governance, capacity plans, and acceptance gates. Use for architecture, sizing assumptions, environment isolation, or cross-workload planning without live data analysis."
---

# Fabric platform design

Follow project AGENTS.md and the active privacy hook. Respect denials without
alternate-tool or identity workarounds. Use fictional examples and approved
technical metadata; never retrieve business rows or ask for their output.
This self-contained skill grants no execution, deployment, or connector access.

## Workflow

1. Read permitted requirements and existing project artifacts. Separate stated
   requirements, assumptions, and best-practice recommendations.
2. Identify sources, owners, trust boundaries, destinations, retention, recovery
   objectives, workload concurrency, and dev/test/prod isolation requirements.
   Do not infer access authorization from resource discovery.
3. Choose Spark, SQL, pipelines, streaming, or semantic models from the required
   outcome. Explain alternatives rather than forcing every workload into Spark.
4. For a medallion design, define immutable Bronze input, validated/conformed
   Silver contracts, and governed Gold serving contracts. Keep source identity,
   batch identity, ingestion time, and replay evidence distinct.
5. Specify schema-enabled lakehouses. Choose separate workspaces/lakehouses
   where access, ownership, retention, or operational isolation requires them;
   bronze/silver/gold schemas alone are not a security-isolation guarantee.
6. Design validation and restart gates: duplicates, null keys, invalid ranges,
   schema drift, partial writes, lost responses, and concurrent runs.
   Never assume cross-table writes are atomic.
7. Plan promotion, rollback, observability, and least-privilege identities.
   Catalog labels, domains, and descriptions are not proof of enforcement.

## Capacity and costs

Ask for region, workload profile, concurrency, and utilization assumptions before
sizing. Distinguish capacity estimates from measured behavior. Do not invent
dollar prices or fetch pricing through an unapproved shell/network path.
Use approved current pricing evidence or provide an explicitly unpriced model.
Do not retrieve raw capacity query history or user activity for sizing.

## Output

Return the architecture, alternatives, configuration/data contracts, dependency
order, acceptance scenarios, and unresolved decisions. Deployment, real-data
checks, and cost measurements are unexecuted unless separately authorized
through implemented controls.

For code authoring use privacy-fabric-authoring; model definitions use
privacy-fabric-modeling; source conversion uses privacy-fabric-migration.
For Fabric-side analysis use privacy-fabric-osmos, whose live dispatch is
currently disabled. A denial is not permission to switch paths.

Adapted from the reviewed Microsoft Fabric Skills revision and sources listed
in the repository's THIRD-PARTY-NOTICES.md; not an upstream execution workflow.
