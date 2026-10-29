---
name: privacy-fabric-migration
description: "Assess and convert reviewed local Databricks, Synapse, HDInsight, and ADF code or pipeline definitions for Fabric. Use for compatibility mapping, migration planning, and offline conversion; no live source inventory, reconciliation, or cutover."
---

# Offline Fabric migration

Follow project AGENTS.md and the active privacy hook. Respect denials without
alternate-tool or identity workarounds. Use reviewed source/configuration files
without embedded secrets or business values. Never execute business-row queries
or request their output. This self-contained skill grants no live access.

## Assessment before conversion

Inventory permitted local notebooks, jobs, pipelines, library declarations,
schemas, and dependencies. Classify each component as directly portable,
adaptable, unsupported, or unknown. Missing source artifacts are missing
evidence, not permission to retrieve unrestricted live definitions.

Map the dependency graph and environment configuration before porting code.
Separate assessment, architecture, conversion, deployment, validation, and
cutover. The last three remain human-operated under the current baseline.

## Conversion checkpoints

| Source | Fabric consideration |
| --- | --- |
| dbutils / mssparkutils | Map supported functionality to notebookutils; flag unsupported behavior rather than mechanical replacement |
| DBFS, mounts, Linked Services | Explicit OneLake paths, Fabric connections, or justified shortcuts; no assumed credential transfer |
| Unity Catalog / Hive namespaces | Schema-enabled lakehouse mapping; assess ownership, permissions, and naming collisions |
| Databricks jobs / Oozie / Synapse orchestration | Pipelines, notebooks, Spark Job Definitions, or other justified targets; preserve retries and dependency semantics |
| Source cluster libraries | Fabric Environment/library compatibility plan; no automatic installs or authentication |
| Dedicated SQL Pool / Hive DDL | Verify target dialect and unsupported features using approved documentation; preserve semantics |

Pipeline JSON needs special attention: Fabric inlines dataset properties;
SynapseNotebook becomes TridentNotebook with a notebook GUID; global parameters
map to Variable Libraries. Confirm connection display-name versus ID fields
against current documentation. Unsupported Validation, SHIR, SSIS, triggers,
or connector behavior must be surfaced, not silently dropped.

## Acceptance and reporting

Create synthetic tests for converted API calls, paths, parameters, dependency
ordering, replay, and failure recovery. Preserve originals and list breaking
changes. Provide unexecuted reconciliation queries with counting semantics;
do not obtain source/target counts yourself.

Shortcuts, Delta, and medallion patterns are options to justify, not mandatory
substitutions for all workloads. Do not equate copied code with a successful
migration or assume source governance automatically transfers.

Return converted files, compatibility matrix, unresolved dependencies,
user-operated validation/cutover steps, and rollback prerequisites.

Adapted from the reviewed Microsoft Fabric Skills revision and sources listed
in THIRD-PARTY-NOTICES.md. No upstream execution helpers are bundled.
