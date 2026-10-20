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
  `src/match.js` runs a curated keyword heuristic (one list per attack class, checked against every function/class node's name and file path — see `ATTACK_CLASS_KEYWORDS`) against WHATEVER application graph was loaded, not a fixed pair of demo node ids. Every `POTENTIALLY_MATCHES` edge it emits is explicitly **hypothetical**, capped at `low`/`medium` confidence, and names the exact keyword + field that triggered it — no demonstrated security failure is ever claimed. Attack classes with zero matching nodes are listed as unresolved hypotheses instead of silently dropped.

- **Point it at a real target**  
  `data/code-atlas-sample.json` is swappable: drop any real Code Atlas `atlas.bundle.json` there (same schema) before `npm run build-graph` to match against that repo's actual code instead of the bundled fixture. `npm run export-overlay` then converts the resulting `POTENTIALLY_MATCHES` edges into Code Atlas's own `--asi-overlay` document format (`data/overlay.json`), so the leads this repo finds can be fed straight back into that same target's Threat Map view in the Code Atlas viewer.

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

## Real counts (after build, against the bundled fixture)

- Nodes: **112** (103 ASI + 9 application)
- Edges: varies with the keyword matcher's hits on the fixture's 9 app nodes
- Every cross-graph edge: hypothetical, never verified

## Limits

- Cross-graph links are a static keyword heuristic, not a data-flow prover: a hit means "worth a human/agent look," not a confirmed vulnerability.
- No full MCP server (endpoints are MCP-adapter ready).
- No new database; pure JSON.

Apache-2.0
