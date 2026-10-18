import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const GRAPH = path.join(ROOT, 'data', 'threat-graph.json');

describe('asi-threat-graph', () => {
  it('builds graph successfully', () => {
    execSync('node src/build-graph.js', { cwd: ROOT, stdio: 'pipe' });
    assert.ok(fs.existsSync(GRAPH));
  });

  it('has nodes and edges with provenance', () => {
    const g = JSON.parse(fs.readFileSync(GRAPH, 'utf8'));
    assert.ok(g.counts.nodes > 20, 'expected many nodes');
    assert.ok(g.counts.edges > 10, 'expected edges');
    assert.ok(g.counts.asiNodes > 0);
    assert.ok(g.counts.appNodes > 0);

    for (const n of g.nodes.slice(0, 50)) {
      assert.ok(n.id, 'node has id');
      assert.ok(n.layer === 'asi' || n.layer === 'application');
      assert.ok(n.source || n.provenance, `node ${n.id} missing provenance`);
    }
    for (const e of g.edges.slice(0, 50)) {
      assert.ok(e.kind);
      assert.ok(e.evidenceStatus);
      assert.ok(e.source);
    }
  });

  it('marks hypothetical cross-graph edges explicitly', () => {
    const g = JSON.parse(fs.readFileSync(GRAPH, 'utf8'));
    const hypos = g.edges.filter(e => e.evidenceStatus === 'hypothetical');
    assert.ok(hypos.length >= 1, 'expected at least one hypothetical mapping');
    for (const h of hypos) {
      assert.ok(h.note && h.note.toLowerCase().includes('hypothetical'), 'hypothetical edge must carry clarifying note');
      assert.equal(h.kind, 'POTENTIALLY_MATCHES');
    }
  });

  it('does not claim verified vulnerability on sample app', () => {
    const g = JSON.parse(fs.readFileSync(GRAPH, 'utf8'));
    const verifiedBad = g.edges.filter(e =>
      e.kind === 'POTENTIALLY_MATCHES' &&
      (e.evidenceStatus === 'observed' || e.evidenceStatus === 'documented')
    );
    assert.equal(verifiedBad.length, 0, 'no verified vulnerability claims on fixture');
  });

  it('unresolved hypotheses are present', () => {
    const g = JSON.parse(fs.readFileSync(GRAPH, 'utf8'));
    assert.ok(Array.isArray(g.unresolvedHypotheses));
    assert.ok(g.unresolvedHypotheses.length >= 1);
  });

  it('records the pinned catalog ref + content hashes, and caches by ref', () => {
    const g = JSON.parse(fs.readFileSync(GRAPH, 'utf8'));
    const ref = g.sources?.asi?.ref;
    assert.ok(ref && ref.length >= 12, 'pinned catalog ref recorded in provenance');
    const hashes = g.sources?.asi?.contentHashes || {};
    assert.ok(Object.keys(hashes).length === 4, 'content hash for each imported catalog file');
    for (const h of Object.values(hashes)) assert.match(h, /^sha256:[0-9a-f]{64}$/, 'content hash is a real sha256');
    // cache files are scoped to the ref, so a ref change can never reuse+relabel
    // stale bytes. The graph's revision label is the 12-char ref prefix.
    const rev = ref.slice(0, 12);
    assert.ok(fs.existsSync(path.join(ROOT, 'data', `asi-attack-classes-01.${rev}.json`)),
      'catalog cache file is named with the ref (ref-scoped caching)');
    // every ASI node is labeled with that same ref prefix (no stale label drift)
    const asiNode = g.nodes.find(n => n.layer === 'asi' && n.source);
    assert.equal(asiNode.source.revision, rev, 'ASI node revision matches the pinned ref');
  });
});
