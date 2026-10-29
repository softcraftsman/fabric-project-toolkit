---
name: privacy-fabric-modeling
description: "Author and review local Power BI TMDL, DAX measures, relationships, and semantic-model contracts from approved schemas. Use for modeling, Direct Lake design, or PBIP definition work without querying live models or retrieving business values."
---

# Local semantic-model authoring

Follow project AGENTS.md and the active privacy hook. Respect denials without
alternate-tool or identity workarounds. Never execute business-row queries or
request business-data output. This self-contained skill grants no live access.

1. Establish approved source schemas, fact grain, dimension keys, business
   definitions, and expected filter behavior. Ask for schema-only information
   or use marked placeholders; do not discover values to fill gaps.
2. Read existing local TMDL/PBIP files and preserve project conventions.
   A registered live modeling server is not authority to connect or mutate.
3. Design a star schema with deliberate cardinality, filter direction, unknown
   members, date relationships, and explicit measures. Explain ambiguity and
   many-to-many tradeoffs rather than hiding them with bidirectional filters.
4. Choose Direct Lake, Import, or DirectQuery from requirements and verified
   capabilities. Model configuration and RLS/OLS definitions are not proof
   that access is enforced; runtime validation remains a separate user step.
5. Write DAX with explicit row/filter-context semantics and null/blank handling.
   Do not hardcode real entity values, report filter literals, or verified
   business answers in fixtures or examples.
6. Use synthetic cases to validate measure semantics locally where supported.
   Provide unexecuted DAX templates for authorized manual validation; distinguish
   syntax review from actual execution and observed performance.

Do not fetch full live schemas, report metadata, INFO/DMV queries, annotations,
value-search results, or query plans. They can carry business values or query
text even when labeled metadata. Refresh, permissions, binding, publication,
and deployment remain outside this skill's grant.

Return changed local definitions, assumptions, synthetic evidence, and manual
deployment/validation instructions. Never present unexecuted measures as results.

Adapted from the reviewed Microsoft Fabric Skills revision and sources listed
in THIRD-PARTY-NOTICES.md; live FabricIQ insights are intentionally excluded.
