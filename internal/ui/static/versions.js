// What is newer than the versions that run, asked from the browser: the
// server may have no way out to the internet, while the people who use it
// usually do. GitHub tells the commits made to Kartal Gözü since the
// server's version; OSV.dev, the open source vulnerability database, the
// known vulnerabilities of a Kubernetes release. Only the repository's name
// and the version numbers are sent, nothing about the clusters.

const GITHUB = 'https://api.github.com';
const OSV = 'https://api.osv.dev';
// The Go module OSV.dev files Kubernetes' own vulnerabilities under, by the
// Kubernetes version.
const MODULE = 'k8s.io/kubernetes';
// How many of the newer commits are told.
export const MAX_LISTED = 20;

// LookupError is a service that could not be asked, or answered an error.
export class LookupError extends Error {
  constructor(host, message, status) {
    super(host + ': ' + message);
    this.host = host;
    this.status = status || 0;
  }
}

// lookup.timeoutMs is how long a service may take to answer. A network that
// drops what goes out would otherwise keep a request waiting for minutes,
// and the page with it.
export const lookup = { timeoutMs: 20000 };

async function getJSON(url, init, signal) {
  const host = new URL(url).host;
  const ctl = new AbortController();
  let late = false;
  const timer = setTimeout(() => {
    late = true;
    ctl.abort();
  }, lookup.timeoutMs);
  const cancel = () => ctl.abort();
  if (signal) {
    if (signal.aborted) ctl.abort();
    else signal.addEventListener('abort', cancel);
  }
  const failed = (e, what) => {
    if (late) return new LookupError(host, 'no answer in ' + Math.round(lookup.timeoutMs / 1000) + ' s');
    if (e && e.name === 'AbortError') return e;
    return new LookupError(host, what);
  };
  try {
    let res;
    try {
      res = await fetch(url, Object.assign({ credentials: 'omit', referrerPolicy: 'no-referrer' }, init, { signal: ctl.signal }));
    } catch (e) {
      throw failed(e, (e && e.message) || 'not reachable');
    }
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const b = await res.json();
        if (b && typeof b.message === 'string' && b.message) msg = b.message;
      } catch { /* the status says enough */ }
      throw new LookupError(host, res.status + (msg ? ' ' + msg : ''), res.status);
    }
    try {
      return await res.json();
    } catch (e) {
      // Such as a proxy's or a sign-in portal's page.
      throw failed(e, 'answered with something other than JSON');
    }
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', cancel);
  }
}

const github = { headers: { Accept: 'application/vnd.github+json' } };

// lookCommits are the newest 100 commits of a repository's default branch,
// newest first.
export async function lookCommits(repo, signal) {
  const list = await getJSON(GITHUB + '/repos/' + repo + '/commits?per_page=100', github, signal);
  return (Array.isArray(list) ? list : []).map(c => ({
    sha: String(c.sha || '').toLowerCase(),
    title: String((c.commit && c.commit.message) || '').split('\n')[0].trim(),
    date: String((c.commit && c.commit.committer && c.commit.committer.date) || ''),
    url: String(c.html_url || ''),
  }));
}

const DESCRIBE = /-g([0-9a-f]{7,40})$/;
const COMMIT = /^[0-9a-f]{7,40}$/;
const TAG = /^v?\d+(\.\d+){0,2}([-+][0-9a-z.-]+)?$/;

// commitOf reads a build version: a commit ("7804c92"), git describe's
// output ("v0.2.0-3-g7804c92"), or a release's tag to look up ("v0.2.0").
// Any other name ("demo") is unnamed: it is not asked about.
export function commitOf(version) {
  let v = String(version || '').trim().toLowerCase();
  const dirty = v.endsWith('-dirty');
  if (dirty) v = v.slice(0, -'-dirty'.length);
  if (!v || v === 'dev') return { dirty, unknown: true };
  const m = DESCRIBE.exec(v);
  if (m) return { sha: m[1], dirty };
  if (COMMIT.test(v)) return { sha: v, dirty };
  if (TAG.test(v)) return { ref: String(version).trim().replace(/-dirty$/i, ''), dirty };
  return { dirty, unnamed: true };
}

// selfState places a commit among the repository's newest ones.
export function selfState(sha, commits, repo) {
  const at = commits.findIndex(c => c.sha.startsWith(sha));
  if (at < 0) return { state: 'unknown', reason: 'notRecent', sha: sha.slice(0, 7), count: commits.length };
  if (at === 0) return { state: 'current' };
  return { state: 'behind', behind: at, commits: commits.slice(0, Math.min(at, MAX_LISTED)), url: 'https://github.com/' + repo + '/commits' };
}

// lookSelf tells how the server's version stands against its repository:
// state is "current", "behind" (behind newer commits, the newest listed)
// or "unknown", with a reason.
export async function lookSelf(version, repo, signal) {
  const c = commitOf(version);
  const out = { version, repo, dirty: c.dirty, state: 'unknown' };
  if (c.unknown) return Object.assign(out, { reason: 'noVersion' });
  if (c.unnamed) return Object.assign(out, { reason: 'notComparable', ref: String(version).trim() });
  let sha = c.sha;
  if (!sha) {
    try {
      const got = await getJSON(GITHUB + '/repos/' + repo + '/commits/' + encodeURIComponent(c.ref), github, signal);
      sha = String((got && got.sha) || '').toLowerCase();
    } catch (e) {
      if (e instanceof LookupError && (e.status === 404 || e.status === 422)) return Object.assign(out, { reason: 'notInRepo', ref: c.ref });
      throw e;
    }
    if (!sha) return Object.assign(out, { reason: 'notInRepo', ref: c.ref });
  }
  return Object.assign(out, selfState(sha, await lookCommits(repo, signal), repo));
}

// byID are the OSV.dev records looked up by their ID during this visit.
const byID = new Map();

// lookVulns asks OSV.dev which vulnerabilities affect a Kubernetes release
// ("1.33.11"), each told once, with the version that fixes it.
export async function lookVulns(version, signal) {
  let entries = [];
  let token = '';
  for (let page = 0; page < 10; page++) {
    const q = { package: { name: MODULE, ecosystem: 'Go' }, version };
    if (token) q.page_token = token;
    const res = await getJSON(OSV + '/v1/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(q) }, signal);
    entries = entries.concat((res && Array.isArray(res.vulns) && res.vulns) || []);
    token = (res && res.next_page_token) || '';
    if (!token) break;
  }
  const vulns = merge(entries, version);
  // Go's reports carry no severity; GitHub's advisory of the same one does,
  // also when it is filed under another module.
  for (const v of vulns) {
    if (v.severity) continue;
    const ghsa = [v.id].concat(v.aliases).find(id => id.startsWith('GHSA-'));
    if (!ghsa) continue;
    try {
      let e = byID.get(ghsa);
      if (!e) {
        e = await getJSON(OSV + '/v1/vulns/' + encodeURIComponent(ghsa), {}, signal);
        byID.set(ghsa, e);
      }
      v.severity = severityOf(e);
      if (!v.summary) v.summary = cleanSummary(e && e.summary);
    } catch (err) {
      if (err && err.name === 'AbortError') throw err;
    }
  }
  sortVulns(vulns);
  return vulns;
}

// merge tells each vulnerability once: GitHub's advisory and Go's report of
// it are joined by their CVE. fixed is the version that fixes it for one at
// version, which may be of a newer minor version; empty when none does yet.
export function merge(entries, version) {
  const at = parseSemver(version);
  const groups = new Map();
  for (const e of entries || []) {
    if (!e || typeof e.id !== 'string' || e.withdrawn) continue;
    const ids = [e.id].concat(Array.isArray(e.aliases) ? e.aliases.map(String) : []).sort();
    const key = ids.find(id => id.startsWith('CVE-')) || e.id;
    let g = groups.get(key);
    if (!g) {
      g = { v: { id: key, aliases: [], summary: '', severity: '', fixed: '', published: '', url: '' }, ids: new Set(), named: false };
      groups.set(key, g);
    }
    ids.forEach(id => g.ids.add(id));
    const ghsa = e.id.startsWith('GHSA-');
    const s = cleanSummary(e.summary);
    if (s && (!g.v.summary || (ghsa && !g.named))) {
      g.v.summary = s;
      g.named = ghsa;
    }
    const sev = severityOf(e);
    if (rank(sev) > rank(g.v.severity)) g.v.severity = sev;
    const pub = Date.parse(e.published);
    if (Number.isFinite(pub) && (!g.v.published || pub < Date.parse(g.v.published))) g.v.published = e.published;
    if (!g.v.url || ghsa) g.v.url = 'https://osv.dev/vulnerability/' + encodeURIComponent(e.id);
    if (at) {
      const f = fixedFor(e, at);
      if (f && (!g.v.fixed || compareSemver(parseSemver(f), parseSemver(g.v.fixed)) < 0)) g.v.fixed = f;
    }
  }
  const out = [];
  for (const [key, g] of groups) {
    g.v.aliases = [...g.ids].filter(id => id !== key).sort();
    out.push(g.v);
  }
  sortVulns(out);
  return out;
}

// fixedFor is the version that fixes an entry for one at version v: the end
// of the range v is in, when that range ends in a fix.
function fixedFor(e, v) {
  for (const a of e.affected || []) {
    if (!a || !a.package || a.package.name !== MODULE) continue;
    for (const r of a.ranges || []) {
      if (r.type !== 'SEMVER' && r.type !== 'ECOSYSTEM') continue;
      const evs = [];
      for (const ev of r.events || []) {
        const kind = ['introduced', 'fixed', 'last_affected', 'limit'].find(k => ev && ev[k]);
        const p = kind && parseSemver(ev[kind]);
        if (p) evs.push({ kind, at: ev[kind], p });
      }
      evs.sort((x, y) => compareSemver(x.p, y.p));
      let open = false;
      let from = null;
      for (const ev of evs) {
        if (ev.kind === 'introduced') {
          open = true;
          from = ev.p;
        } else {
          if (ev.kind === 'fixed' && open && compareSemver(v, from) >= 0 && compareSemver(v, ev.p) < 0) return ev.at;
          open = false;
        }
      }
    }
  }
  return '';
}

// severityOf is the database's word for how bad it is, as GitHub's
// advisories give it.
function severityOf(e) {
  const s = String((e && e.database_specific && e.database_specific.severity) || '').trim().toUpperCase();
  if (s === 'MEDIUM') return 'MODERATE';
  return ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(s) ? s : '';
}

// cleanSummary drops the " in k8s.io/kubernetes" Go's reports end with.
function cleanSummary(s) {
  return String(s || '').trim().replace(/\s+in k8s\.io\/\S+$/, '');
}

export function rank(severity) {
  return { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1 }[severity] || 0;
}

// sortVulns puts the worst first, then those with a fix, then the newest.
export function sortVulns(vs) {
  vs.sort((a, b) => rank(b.severity) - rank(a.severity) || (b.fixed ? 1 : 0) - (a.fixed ? 1 : 0) ||
    (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return vs;
}

// parseSemver reads a version as OSV.dev compares them: numbers, then a
// pre-release, which comes before the release ("1.32.0-alpha.0" < "1.32.0").
export function parseSemver(s) {
  s = String(s == null ? '' : s).trim().replace(/^v/, '');
  if (!s) return null;
  s = s.split('+')[0];
  const dash = s.indexOf('-');
  const core = dash < 0 ? s : s.slice(0, dash);
  const parts = core.split('.');
  if (parts.length > 3) return null;
  const n = [0, 0, 0];
  for (let i = 0; i < parts.length; i++) {
    if (!/^\d+$/.test(parts[i])) return null;
    n[i] = Number(parts[i]);
  }
  return { n, pre: dash < 0 ? [] : s.slice(dash + 1).split('.') };
}

export function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) if (a.n[i] !== b.n[i]) return a.n[i] < b.n[i] ? -1 : 1;
  if (!a.pre.length || !b.pre.length) return (b.pre.length ? 1 : 0) - (a.pre.length ? 1 : 0);
  for (let i = 0; i < Math.min(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i];
    const y = b.pre[i];
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    } else if (xn) return -1;
    else if (yn) return 1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return Math.sign(a.pre.length - b.pre.length);
}
