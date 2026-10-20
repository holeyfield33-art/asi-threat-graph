/**
 * Convert the just-built threat-graph.json (ASI attack classes <-> whichever
 * application graph was loaded) into Code Atlas's --asi-overlay document
 * shape (schemaVersion "1"; see code-atlas/docs/threat-overlay.md), so the
 * matches this repo finds can be fed straight back into Code Atlas's own
 * Threat Map view for the SAME target repo they were matched against.
 *
 * Node ids in threat-graph.json are prefixed "ATLAS:<realId>" (see
 * build-graph.js); the overlay's `target` strips that prefix back off, since
 * Code Atlas's own resolveTarget() matches bare node ids directly.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.join(__dirname, '..', 'data');
const graph = JSON.parse(fs.readFileSync(path.join(DATA, 'threat-graph.json'), 'utf8'));

const acById = new Map(graph.nodes.filter((n) => n.layer === 'asi').map((n) => [n.id, n]));

const leads = graph.edges
  .filter((e) => e.kind === 'POTENTIALLY_MATCHES')
  .map((e, i) => {
    const ac = acById.get(e.from);
    return {
      id: e.id || `lead-${i}`,
      attackClassId: e.from,
      label: ac?.label || e.from,
      target: e.to.replace(/^ATLAS:/, ''),
      status: e.evidenceStatus === 'hypothetical' ? 'hypothetical' : 'inferred',
      confidence: e.confidence || 'low',
      note: e.note || '',
      rule: e.source?.rule,
      evidence: [],
    };
  });

const unresolved = (graph.unresolvedHypotheses || [])
  .filter((u) => u.relatedAppNode) // overlay schema requires a target string when present; omit class-only misses
  .map((u) => ({
    id: u.id,
    attackClassId: u.relatedAttackClass,
    description: u.description,
    target: String(u.relatedAppNode).replace(/^ATLAS:/, ''),
  }));

const overlay = {
  schemaVersion: '1',
  source: {
    identity: 'asi-threat-graph',
    ref: graph.sources?.asi?.ref?.slice(0, 12) || 'unknown',
    asOf: graph.generatedAt?.slice(0, 10) || new Date().toISOString().slice(0, 10),
  },
  leads,
  unresolved,
};

const outPath = path.join(DATA, 'overlay.json');
fs.writeFileSync(outPath, JSON.stringify(overlay, null, 2));
console.log(`Wrote ${outPath}`);
console.log(`${leads.length} lead(s), ${unresolved.length} unresolved entr(y/ies)`);
