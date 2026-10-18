/**
 * ASI Threat Graph — Build unified graph from ASI catalog + Code Atlas sample.
 * Provenance and evidence status are preserved. No fabricated vulnerability claims.
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const DATA = path.join(ROOT, 'data');
const OUT = path.join(DATA, 'threat-graph.json');

// Pin the ASI catalog to an immutable commit so builds are reproducible and the
// recorded provenance is truthful (fetching from `main` would stamp a fixed
// revision label onto whatever main happened to be). Override with ASI_CATALOG_REF.
const CATALOG_REF = process.env.ASI_CATALOG_REF || 'f5b4bfe139718a50308b0ee58cbb5f0e248599fa';
const catalogRevision = CATALOG_REF.slice(0, 12);

const ASI_FILES = ['attack-classes-01', 'attack-classes-02', 'mitigations', 'sources'];

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function sha256File(p) {
  return 'sha256:' + crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

async function ensureAsiData() {
  if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
  for (const base of ASI_FILES) {
    const dest = path.join(DATA, `asi-${base}.json`);
    if (fs.existsSync(dest)) continue;
    const url = `https://raw.githubusercontent.com/holeyfield33-art/agent-security-index/${CATALOG_REF}/public/export/${base}.json`;
    console.log('Fetching', `asi-${base}.json`, 'from', CATALOG_REF.slice(0, 12), '...');
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
    fs.writeFileSync(dest, await res.text());
  }
  // Content hashes of exactly what was imported — provenance you can verify.
  const contentHashes = {};
  for (const base of ASI_FILES) contentHashes[`asi-${base}.json`] = sha256File(path.join(DATA, `asi-${base}.json`));
  return contentHashes;
}

async function build() {
  const catalogHashes = await ensureAsiData();
  const ac1 = loadJson(path.join(DATA, 'asi-attack-classes-01.json'));
  const ac2 = loadJson(path.join(DATA, 'asi-attack-classes-02.json'));
  const mitigations = loadJson(path.join(DATA, 'asi-mitigations.json'));
  const sources = loadJson(path.join(DATA, 'asi-sources.json'));
  const atlas = loadJson(path.join(DATA, 'code-atlas-sample.json'));

  const attackClasses = [...ac1, ...ac2];
  const nodes = [];
  const edges = [];
  const nodeIndex = new Map();

  function addNode(n) {
    if (nodeIndex.has(n.id)) return;
    nodeIndex.set(n.id, n);
    nodes.push(n);
  }

  function addEdge(e) {
    edges.push(e);
  }

  // --- ASI Knowledge Layer ---
  for (const ac of attackClasses) {
    addNode({
      id: ac.id,
      layer: 'asi',
      type: 'attack_class',
      label: ac.name,
      description: ac.oneLine || ac.description?.slice(0, 200),
      family: ac.family,
      evidenceTier: ac.evidenceTier,
      evidenceStatus: ac.evidenceTier === 'T2_field_incident' || ac.evidenceTier === 'T3_widespread' ? 'documented' : 'unverified',
      confidence: ac.evidenceConfidence || 'medium',
      cveIds: ac.cveIds || [],
      owasp: ac.owasp || [],
      source: {
        identity: 'agent-security-index',
        revision: catalogRevision,
        path: `public/export/attack-classes-*.json`,
        status: 'observed'
      },
      provenance: {
        importedFrom: 'ASI Catalog',
        asOf: '2026-10-17'
      }
    });

    for (const o of (ac.owasp || [])) {
      const oid = `OWASP:${o}`;
      addNode({
        id: oid,
        layer: 'asi',
        type: 'owasp',
        label: o,
        description: `OWASP category ${o}`,
        evidenceStatus: 'documented',
        confidence: 'high',
        source: {
          identity: 'agent-security-index',
          revision: catalogRevision,
          status: 'observed'
        }
      });
      addEdge({
        id: `edge-${ac.id}-maps-${oid}`,
        from: ac.id,
        to: oid,
        kind: 'MAPS_TO',
        evidenceStatus: 'observed',
        confidence: 'high',
        source: { identity: 'ASI Catalog owasp field', status: 'observed' }
      });
    }

    for (const cve of (ac.cveIds || [])) {
      const cid = `CVE:${cve}`;
      addNode({
        id: cid,
        layer: 'asi',
        type: 'cve',
        label: cve,
        description: `CVE referenced by ${ac.id}`,
        evidenceStatus: 'documented',
        confidence: 'high',
        source: {
          identity: 'agent-security-index',
          revision: catalogRevision,
          status: 'observed'
        }
      });
      addEdge({
        id: `edge-${ac.id}-rel-${cid}`,
        from: ac.id,
        to: cid,
        kind: 'RELATED_TO',
        evidenceStatus: 'observed',
        confidence: 'high',
        source: { identity: 'ASI Catalog cveIds', status: 'observed' }
      });
    }

    for (const mid of [...(ac.proposedMitigationIds || []), ...(ac.validatedMitigationIds || [])]) {
      const mnode = mitigations.find(m => m.id === mid);
      if (!mnode) continue;
      const midFull = `MIT:${mid}`;
      addNode({
        id: midFull,
        layer: 'asi',
        type: 'mitigation',
        label: mnode.name || mid,
        description: mnode.summary || '',
        evidenceStatus: mnode.validated ? 'documented' : 'unverified',
        confidence: mnode.validated ? 'medium' : 'low',
        source: {
          identity: 'agent-security-index',
          revision: catalogRevision,
          status: 'observed'
        }
      });
      addEdge({
        id: `edge-${ac.id}-mit-${mid}`,
        from: ac.id,
        to: midFull,
        kind: 'MITIGATED_BY',
        evidenceStatus: mnode.validated ? 'documented' : 'inferred',
        confidence: mnode.validated ? 'medium' : 'low',
        source: { identity: 'ASI Catalog mitigationIds', status: 'observed' }
      });
    }
  }

  for (const src of sources.slice(0, 30)) {
    const sid = `SRC:${src.id}`;
    addNode({
      id: sid,
      layer: 'asi',
      type: 'source',
      label: src.title?.slice(0, 60) || src.id,
      description: src.summary || src.notes || '',
      evidenceStatus: 'documented',
      confidence: 'high',
      source: {
        identity: 'agent-security-index',
        revision: catalogRevision,
        url: src.url,
        status: 'observed'
      }
    });
    for (const acid of (src.supports?.attackClassIds || [])) {
      if (nodeIndex.has(acid)) {
        addEdge({
          id: `edge-${acid}-sup-${sid}`,
          from: acid,
          to: sid,
          kind: 'SUPPORTED_BY',
          evidenceStatus: 'observed',
          confidence: 'high',
          source: { identity: 'ASI Catalog source.supports', status: 'observed' }
        });
      }
    }
  }

  const atlasNodes = atlas.graph?.nodes || [];
  const atlasEdges = atlas.graph?.edges || [];
  const routes = atlas.routes || [];

  for (const n of atlasNodes) {
    addNode({
      id: `ATLAS:${n.id}`,
      layer: 'application',
      type: n.kind,
      label: n.label,
      description: `${n.kind} ${n.label}`,
      evidenceStatus: 'observed',
      confidence: 'high',
      source: {
        identity: 'code-atlas-sample',
        revision: atlas.repository?.revision || 'fixture',
        path: n.evidence?.path,
        line: n.evidence?.line,
        contentHash: n.evidence?.contentHash,
        method: n.evidence?.method,
        status: 'observed'
      },
      provenance: {
        importedFrom: 'Code Atlas fixture',
        asOf: atlas.generatedAt
      }
    });
  }

  for (const e of atlasEdges) {
    const kindMap = { contains: 'CONTAINS', imports: 'IMPORTS', calls: 'CALLS' };
    addEdge({
      id: `ATLAS:${e.id}`,
      from: `ATLAS:${e.from}`,
      to: `ATLAS:${e.to}`,
      kind: kindMap[e.kind] || e.kind.toUpperCase(),
      evidenceStatus: e.confidence === 'inferred' ? 'inferred' : 'observed',
      confidence: e.confidence === 'inferred' ? 'low' : 'high',
      source: {
        identity: 'code-atlas-sample',
        revision: atlas.repository?.revision,
        path: e.evidence?.path,
        line: e.evidence?.line,
        status: e.confidence === 'inferred' ? 'inferred' : 'observed'
      }
    });
  }

  for (const r of routes) {
    const rid = `ROUTE:${r.method}:${r.path}`;
    addNode({
      id: rid,
      layer: 'application',
      type: 'route',
      label: `${r.method} ${r.path}`,
      description: `HTTP route ${r.method} ${r.path} (${r.framework})`,
      evidenceStatus: 'observed',
      confidence: 'high',
      source: {
        identity: 'code-atlas-sample',
        revision: atlas.repository?.revision,
        path: r.evidence?.path,
        line: r.evidence?.line,
        status: 'observed'
      }
    });
    if (r.nodeRef) {
      addEdge({
        id: `edge-${rid}-to-handler`,
        from: rid,
        to: `ATLAS:${r.nodeRef}`,
        kind: 'ROUTES_TO',
        evidenceStatus: 'observed',
        confidence: 'high',
        source: {
          identity: 'code-atlas-sample routes',
          status: 'observed'
        }
      });
    }
  }

  const hypoFrom = 'AAC-01';
  const hypoTo = 'ATLAS:fn:src/server.ts#handlePrompt';
  if (nodeIndex.has(hypoFrom) && nodeIndex.has(hypoTo)) {
    addEdge({
      id: 'edge-hypo-aac01-handlePrompt',
      from: hypoFrom,
      to: hypoTo,
      kind: 'POTENTIALLY_MATCHES',
      evidenceStatus: 'hypothetical',
      confidence: 'low',
      note: 'Hypothetical mapping for demonstration only. No verified vulnerability or security failure demonstrated in the sample application. Do not treat as confirmed exposure.',
      source: {
        identity: 'mvp-demo-rule',
        status: 'inferred',
        rule: 'prompt-handling-function-name-heuristic'
      }
    });
  }

  const hypo2From = 'AAC-07';
  const hypo2To = 'ATLAS:fn:src/tools.ts#executeShell';
  if (nodeIndex.has(hypo2From) && nodeIndex.has(hypo2To)) {
    addEdge({
      id: 'edge-hypo-aac07-executeShell',
      from: hypo2From,
      to: hypo2To,
      kind: 'POTENTIALLY_MATCHES',
      evidenceStatus: 'hypothetical',
      confidence: 'low',
      note: 'Hypothetical mapping. Shell execution capability is present; no demonstrated failure path from an attack class is claimed.',
      source: {
        identity: 'mvp-demo-rule',
        status: 'inferred',
        rule: 'tool-execution-surface-heuristic'
      }
    });
  }

  const unresolved = [
    {
      id: 'hyp-unresolved-auth-bypass',
      description: 'No verified mapping from AAC-29 (auth-related) to checkAuth in this fixture.',
      status: 'unresolved',
      relatedAttackClass: 'AAC-29',
      relatedAppNode: 'ATLAS:fn:src/auth.ts#checkAuth'
    }
  ];

  const graph = {
    schemaVersion: '0.1.0',
    generatedAt: new Date().toISOString(),
    sources: {
      asi: {
        identity: 'holeyfield33-art/agent-security-index',
        revision: catalogRevision,
        ref: CATALOG_REF,
        contentHashes: catalogHashes
      },
      atlas: { identity: 'code-atlas-sample', revision: atlas.repository?.revision }
    },
    counts: {
      nodes: nodes.length,
      edges: edges.length,
      asiNodes: nodes.filter(n => n.layer === 'asi').length,
      appNodes: nodes.filter(n => n.layer === 'application').length,
      hypotheticalEdges: edges.filter(e => e.evidenceStatus === 'hypothetical').length
    },
    nodes,
    edges,
    unresolvedHypotheses: unresolved
  };

  fs.writeFileSync(OUT, JSON.stringify(graph, null, 2));
  console.log(`Wrote ${OUT}`);
  console.log(`Nodes: ${graph.counts.nodes}  Edges: ${graph.counts.edges}`);
  console.log(`ASI nodes: ${graph.counts.asiNodes}  App nodes: ${graph.counts.appNodes}`);
  console.log(`Hypothetical edges: ${graph.counts.hypotheticalEdges}`);
  return graph;
}

build().catch(err => { console.error(err); process.exit(1); });
