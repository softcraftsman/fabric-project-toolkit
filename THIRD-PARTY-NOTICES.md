# Third-party notices and curated provenance

The six `skills\privacy-fabric-*\SKILL.md` files and the workload-routing additions
to the existing agents adapt selected concepts from
[Microsoft Skills for Fabric](https://github.com/microsoft/skills-for-fabric)
at revision `4c3986d2e5b498ce2d6e6025533b94b5e5bb2ccd`.
They are curated adaptations, not complete upstream skills or Microsoft-certified
privacy controls. Existing nine toolkit agent roles are preserved.

| Curated skill | Reviewed upstream sources |
| --- | --- |
| privacy-fabric-design | agents/FabricDataEngineer.agent.md, agents/FabricAdmin.agent.md, skills/e2e-medallion-architecture/SKILL.md, skills/e2e-fabric-cost-estimation/SKILL.md, common/COMMON-CORE.md |
| privacy-fabric-authoring | skills/spark-cli/SKILL.md, skills/sqldw-cli/SKILL.md, common/COMMON-CORE.md |
| privacy-fabric-modeling | skills/semantic-model-authoring/SKILL.md |
| privacy-fabric-migration | agents/FabricMigrationEngineer.agent.md, skills/pipeline-migration/SKILL.md |
| privacy-fabric-integration | agents/FabricAppDev.agent.md, skills/dataflows-cli/SKILL.md, skills/pipeline-migration/SKILL.md |
| privacy-fabric-osmos | skills/project-osmos/SKILL.md |

No upstream MCP registrations, executable helpers, automatic-update mechanisms,
or root agent instructions are imported. Review source changes, dependencies,
privacy behavior, and synthetic regressions before updating this revision.
Upstream technical guidance is not an authoritative API contract; verify specific
syntax and current capabilities through approved Microsoft documentation.

## Microsoft Skills for Fabric license

MIT License

Copyright (c) 2026 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
