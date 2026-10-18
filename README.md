# ASI Threat Graph

Working MVP: interactive, evidence-backed security threat graph connecting **ASI attack classes** (from [agent-security-index](https://github.com/holeyfield33-art/agent-security-index)) to **Code Atlas** application graphs.

**Hard rules observed:** no fabricated vulnerability claims, no invented attack classes/CVEs, provenance preserved, hypothetical mappings clearly marked.

## Clean clone & one-command startup

```bash
git clone https://github.com/holeyfield33-art/asi-threat-graph.git
cd asi-threat-graph
npm run build-graph   # fetches ASI catalog JSON if missing, writes data/threat-graph.json
npm test              # 5 tests, no extra deps
npm install           # express only needed for the server/viewer
PORT=3847 npm start   # http://localhost:3847
```

`build-graph` auto-downloads ASI export JSON from `agent-security-index` when absent. The Code Atlas sample fixture is committed under `data/code-atlas-sample.json`.

## What you get

- **Threat Knowledge Graph (ASI)**  
  Nodes: AAC attack classes, OWASP, CVEs, mitigations, sources.  
  Edges: MAPS_TO, RELATED_TO, MITIGATED_BY, SUPPORTED_BY.

- **Application Threat Graph (Code Atlas sample)**  
  Nodes: files, functions, HTTP routes.  
  Edges: CONTAINS, CALLS, ROUTES_TO.

- **Cross-graph**  
  Only `POTENTIALLY_MATCHES` edges that are explicitly **hypothetical** (no demonstrated security failure in the fixture). Unresolved hypotheses listed separately.

- **Viewer**  
  Pan / zoom / drag, color by type, click for description + source + confidence + evidence, search, layer & evidence-status filters.

- **Agent-readable API** (read-only, versioned)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/graph` | Full graph JSON |
| `GET /api/v1/nodes/:id` | Node + neighbors |
| `GET /api/v1/edges/:id/evidence` | Evidence for an edge |
| `GET /api/v1/match/:attackClassId` | App nodes potentially matching an AAC |
| `GET /api/v1/trace/route?route=...` | Trace route through CALLS/ROUTES_TO |
| `GET /api/v1/hypotheses/unresolved` | Unresolved security hypotheses |
| `GET /api/v1/search?q=...` | Search nodes |
| `GET /api/v1/stats` | Counts |
| `GET /api/v1/export` | Download graph JSON |

## Data sources (no invention)

- ASI: `public/export/*.json` from holeyfield33-art/agent-security-index (fetched at build time)
- Application: fixture shaped exactly to Code Atlas schema (`AtlasBundle` / graph nodes & edges)

## Tests

```bash
npm test
```

Covers import, provenance presence, status labels, and that hypothetical edges are never presented as verified vulnerabilities.

## Real counts (after build)

- Nodes: **112** (103 ASI + 9 application)
- Edges: **204**
- Hypothetical cross-graph edges: **2**

## Example path (hypothetical)

`AAC-01 (Direct Prompt Injection)` --POTENTIALLY_MATCHES--> `ATLAS:fn:src/server.ts#handlePrompt` <--ROUTES_TO-- `ROUTE:POST:/api/prompt`

Marked hypothetical; no verified failure claimed.

## Limits of this MVP

- Sample application graph only (no live GitLab/SurfaceTrace dependency).
- Cross-graph links are heuristic and marked hypothetical.
- No full MCP server (endpoints are MCP-adapter ready).
- No new database; pure JSON.

Apache-2.0
