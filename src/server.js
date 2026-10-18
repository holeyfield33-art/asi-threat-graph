/**
 * Read-only API + static viewer for ASI Threat Graph.
 * Designed so a future MCP adapter can call the same endpoints.
 */
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const GRAPH_PATH = path.join(ROOT, 'data', 'threat-graph.json');

const app = express();
const PORT = process.env.PORT || 3847;

function loadGraph() {
  if (!fs.existsSync(GRAPH_PATH)) {
    throw new Error('threat-graph.json missing. Run: npm run build-graph');
  }
  return JSON.parse(fs.readFileSync(GRAPH_PATH, 'utf8'));
}

app.use(express.static(path.join(ROOT, 'src', 'viewer')));

// Versioned export
app.get('/api/v1/graph', (req, res) => {
  res.json(loadGraph());
});

app.get('/api/v1/export', (req, res) => {
  res.download(GRAPH_PATH, 'threat-graph.json');
});

// Get a node and its neighbors
app.get('/api/v1/nodes/:id', (req, res) => {
  const g = loadGraph();
  const id = decodeURIComponent(req.params.id);
  const node = g.nodes.find(n => n.id === id);
  if (!node) return res.status(404).json({ error: 'node not found' });
  const neighbors = g.edges
    .filter(e => e.from === id || e.to === id)
    .map(e => {
      const otherId = e.from === id ? e.to : e.from;
      return { edge: e, node: g.nodes.find(n => n.id === otherId) };
    });
  res.json({ node, neighbors });
});

// Evidence supporting an edge
app.get('/api/v1/edges/:id/evidence', (req, res) => {
  const g = loadGraph();
  const id = decodeURIComponent(req.params.id);
  const edge = g.edges.find(e => e.id === id);
  if (!edge) return res.status(404).json({ error: 'edge not found' });
  res.json({
    edgeId: edge.id,
    kind: edge.kind,
    evidenceStatus: edge.evidenceStatus,
    confidence: edge.confidence,
    note: edge.note || null,
    source: edge.source,
    from: edge.from,
    to: edge.to
  });
});

// Find application nodes potentially matching an attack class
app.get('/api/v1/match/:attackClassId', (req, res) => {
  const g = loadGraph();
  const acid = decodeURIComponent(req.params.attackClassId);
  const matches = g.edges
    .filter(e => e.from === acid && e.kind === 'POTENTIALLY_MATCHES')
    .map(e => ({
      edge: e,
      appNode: g.nodes.find(n => n.id === e.to)
    }));
  res.json({ attackClassId: acid, matches, note: 'Matches may be hypothetical; check evidenceStatus.' });
});

// Trace a route through known function relationships
app.get('/api/v1/trace/route', (req, res) => {
  const g = loadGraph();
  const routeId = req.query.route;
  if (!routeId) return res.status(400).json({ error: 'query param route required' });
  const routeNode = g.nodes.find(n => n.id === routeId || (n.type === 'route' && n.label.includes(routeId)));
  if (!routeNode) return res.status(404).json({ error: 'route not found' });

  // BFS along CALLS / ROUTES_TO / CONTAINS
  const visited = new Set();
  const tracePath = []; // not `path` — that name is the imported node:path module
  const queue = [routeNode.id];
  while (queue.length) {
    const cur = queue.shift();
    if (visited.has(cur)) continue;
    visited.add(cur);
    const n = g.nodes.find(x => x.id === cur);
    tracePath.push(n);
    const outs = g.edges.filter(e => e.from === cur && ['ROUTES_TO', 'CALLS', 'CONTAINS'].includes(e.kind));
    for (const e of outs) queue.push(e.to);
  }
  res.json({ route: routeNode, path: tracePath });
});

// Unresolved security hypotheses
app.get('/api/v1/hypotheses/unresolved', (req, res) => {
  const g = loadGraph();
  res.json({ unresolved: g.unresolvedHypotheses || [] });
});

// Search
app.get('/api/v1/search', (req, res) => {
  const g = loadGraph();
  const q = (req.query.q || '').toLowerCase();
  if (!q) return res.status(400).json({ error: 'q required' });
  const results = g.nodes.filter(n =>
    n.id.toLowerCase().includes(q) ||
    (n.label || '').toLowerCase().includes(q) ||
    (n.description || '').toLowerCase().includes(q) ||
    (n.cveIds || []).some(c => c.toLowerCase().includes(q))
  ).slice(0, 50);
  res.json({ query: q, results });
});

// Counts / health
app.get('/api/v1/stats', (req, res) => {
  const g = loadGraph();
  res.json(g.counts);
});

app.listen(PORT, () => {
  console.log(`ASI Threat Graph viewer + API on http://localhost:${PORT}`);
  console.log(`Graph export: http://localhost:${PORT}/api/v1/graph`);
});
