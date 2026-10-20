/**
 * General attack-class -> application-node matcher.
 *
 * Replaces the two hardcoded demo edges that used to stand in for this. Those
 * checked two literal node-id strings that only existed in the bundled fixture,
 * so they produced zero matches against any real target. This module is a
 * genuine (if simple) static heuristic: each attack class carries a curated
 * keyword list drawn from its own name/family/oneLine, and a node matches when
 * one of those keywords appears in its (tokenized) label or file path.
 *
 * Hard rule preserved: every match is `status: 'hypothetical'`, `confidence`
 * capped at 'medium' (name-match) or 'low' (path-only match) — never 'high',
 * never 'verified'/'observed'. A keyword hit is a reason to look, not a claim
 * that anything is actually wrong. The matched keyword + field is recorded on
 * every edge so the mapping is auditable, not a black box.
 */

// Curated per-class keyword lists. Each keyword is checked as a lowercase
// substring against a lowercased, delimiter-normalized token of the node's
// label and (separately, at lower confidence) its file path. Keep lists
// specific enough that a hit is actually informative, not generic noise.
export const ATTACK_CLASS_KEYWORDS = {
  'AAC-01': ['prompt', 'systemprompt', 'userprompt', 'completion', 'chatcompletion', 'llmcall', 'generatetext'],
  'AAC-02': ['retrieve', 'rag', 'scrape', 'fetchurl', 'webpage', 'crawl', 'ingest', 'loaddocument'],
  'AAC-03': ['tooldescription', 'mcptool', 'tooldef', 'toolschema', 'registertool'],
  'AAC-04': ['toolregistry', 'toolname', 'shadowtool', 'overridetool'],
  'AAC-05': ['mcpserver', 'toolupdate', 'descriptorhash', 'rugpull', 'mcpclient'],
  'AAC-06': ['memory', 'memorywrite', 'persistmemory', 'longtermmemory', 'memorystore'],
  'AAC-07': ['scope', 'permission', 'grantaccess', 'privilege', 'escalate', 'elevate'],
  'AAC-08': ['onbehalfof', 'impersonate', 'delegate', 'proxyrequest', 'actas', 'assumerole'],
  'AAC-09': ['token', 'apikey', 'secret', 'credential', 'authtoken', 'accesstoken', 'refreshtoken'],
  'AAC-10': ['install', 'npminstall', 'pipinstall', 'plugin', 'extension', 'dependency', 'packageinstall'],
  'AAC-11': ['exec', 'execsync', 'execfile', 'spawn', 'shellexec', 'system', 'childprocess'],
  'AAC-12': ['toolresult', 'toolresponse', 'contextinject', 'goalhijack'],
  'AAC-13': ['mcpauth', 'bearertoken', 'apikeyauth', 'noauth', 'authenticate'],
  'AAC-14': ['mcpdiscover', 'mcpregistry', 'serverdiscovery', 'unregistered'],
  'AAC-15': ['sendcontext', 'sharecontext', 'fullcontext', 'contextoversharing'],
  'AAC-16': ['stdio', 'spawnstdio', 'mcpstdio', 'childprocess'],
  'AAC-17': ['readfile', 'writefile', 'resolvepath', 'traversal', 'sanitizepath', 'fsescape', 'joinpath'],
  'AAC-18': ['hiddencall', 'silenttool', 'backgroundcall', 'unlistedtool'],
  'AAC-19': ['invocationcount', 'delayedpayload', 'triggerafter', 'gatedpayload'],
  'AAC-20': ['agentcard', 'a2acard', 'capabilitytext', 'agentdescriptor'],
};

/** Lowercase and strip camelCase/snake_case/kebab-case delimiters into one
 *  contiguous token, so "execSync", "exec_sync" and "exec-sync" all normalize
 *  to "execsync" and match the same keyword. */
function normalize(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/**
 * @param {Array<{id:string,name:string,family?:string,oneLine?:string}>} attackClasses
 * @param {Array<{id:string,kind:string,label:string,evidence?:{path?:string}}>} atlasNodes - RAW Code Atlas graph nodes (unprefixed ids)
 * @returns {{ edges: Array<object>, unresolved: Array<object> }}
 */
export function matchAttackClasses(attackClasses, atlasNodes) {
  const matchable = atlasNodes.filter((n) => n.kind === 'function' || n.kind === 'class');
  const edges = [];
  const unresolved = [];

  for (const ac of attackClasses) {
    const keywords = ATTACK_CLASS_KEYWORDS[ac.id] || [];
    if (keywords.length === 0) {
      unresolved.push({
        id: `hyp-unresolved-${ac.id}`,
        description: `No keyword mapping defined yet for ${ac.id} (${ac.name}).`,
        status: 'unresolved',
        relatedAttackClass: ac.id,
        relatedAppNode: null,
      });
      continue;
    }

    let hits = 0;
    for (const n of matchable) {
      const nameTok = normalize(n.label);
      const pathTok = normalize(n.evidence?.path);
      const nameHit = keywords.find((k) => nameTok.includes(normalize(k)));
      const pathHit = !nameHit ? keywords.find((k) => pathTok.includes(normalize(k))) : null;
      const hitKeyword = nameHit || pathHit;
      if (!hitKeyword) continue;

      hits++;
      edges.push({
        id: `edge-match-${ac.id}-${n.id}`,
        from: ac.id,
        to: `ATLAS:${n.id}`,
        kind: 'POTENTIALLY_MATCHES',
        evidenceStatus: 'hypothetical',
        confidence: nameHit ? 'medium' : 'low',
        note: `Hypothetical mapping from a keyword heuristic only: "${hitKeyword}" found in this node's ${nameHit ? 'name' : 'file path'}. No demonstrated security failure; needs manual/agent verification before treating as a real exposure.`,
        source: {
          identity: 'asi-threat-graph-matcher',
          status: 'inferred',
          rule: `keyword:${hitKeyword}`,
        },
      });
    }

    if (hits === 0) {
      unresolved.push({
        id: `hyp-unresolved-${ac.id}`,
        description: `No application node's name or file path matched any of this class's keywords (${keywords.join(', ')}).`,
        status: 'unresolved',
        relatedAttackClass: ac.id,
        relatedAppNode: null,
      });
    }
  }

  return { edges, unresolved };
}
