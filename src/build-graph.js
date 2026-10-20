/**
 * ASI Threat Graph — Build unified graph from ASI catalog + Code Atlas sample.
 * Provenance and evidence status are preserved. No fabricated vulnerability claims.
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { matchAttackClasses } from './match.js';

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

// Cache path is SCOPED TO THE REF. A different ASI_CATALOG_REF (or a stale
// pre-pin file fetched from `main`) therefore never gets reused and re-labeled:
// the ref is in the filename, so a ref change forces a fresh download. Without
// this, cached bytes from one ref could be stamped with — and hashed under —
// another ref, silently defeating the provenance guarantee.
const fileFor = (base) => path.join(DATA, `asi-${base}.${catalogRevision}.json`);

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function sha256File(p) {
  return 'sha256:' + crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

async function ensureAsiData() {
  if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
  for (const base of ASI_FILES) {
    const dest = fileFor(base);
    if (fs.existsSync(dest)) continue; // safe to reuse: filename is ref-scoped
    const url = `https://raw.githubusercontent.com/holeyfield33-art/agent-security-index/${CATALOG_REF}/public/export/${base}.json`;
    console.log('Fetching', `asi-${base}.json`, 'from', catalogRevision, '...');
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
    fs.writeFileSync(dest, await res.text());
  }
  // Content hashes of exactly what was imported — provenance you can verify.
  // Keyed by the stable logical name; the ref is recorded separately in sources.asi.
  const contentHashes = {};
  for (const base of ASI_FILES) contentHashes[`asi-${base}.json`] = sha256File(fileFor(base));
  return contentHashes;
}

async function build() {
  const catalogHashes = await ensureAsiData();
  const ac1 = loadJson(fileFor('attack-classes-01'));
  const ac2 = loadJson(fileFor('attack-classes-02'));
  const mitigations = loadJson(fileFor('mitigations'));
  const sources = loadJson(fileFor('sources'));
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

  // General keyword-heuristic matcher: runs against WHATEVER application graph was
  // loaded above (the fixture, or a real target's own Code Atlas bundle swapped into
  // data/code-atlas-sample.json), not two hardcoded node-id strings that only ever
  // existed in the bundled fixture. Every edge it emits is hypothetical/inferred —
  // never upgraded — and names the exact keyword + field that triggered it.
  const matched = matchAttackClasses(attackClasses, atlasNodes);
  for (const e of matched.edges) {
    if (nodeIndex.has(e.from) && nodeIndex.has(e.to)) addEdge(e);
  }

  const unresolved = matched.unresolved;

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
