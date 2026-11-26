// The image registry's pages: its projects, a project, a repository's
// artifacts, an artifact, and the robot accounts. app.js hands in its
// helpers (ui) and the data it loaded with loadRegistry; nothing here keeps
// state of its own.

export const REGISTRY_VIEWS = ['registry', 'regproject', 'regrepo', 'regartifact', 'regrunning', 'regjobs', 'regreplication', 'regsources', 'robots'];

const enc = encodeURIComponent;

// loadRegistry asks the server for what a page shows.
export async function loadRegistry(view, rest, api, signal) {
  const info = await api('registry', { signal });
  switch (view) {
    case 'registry':
      return { info, projects: await api('registry/projects', { signal }) };
    case 'regproject': {
      const name = rest[0] || '';
      const [project, repos] = await Promise.all([
        api('registry/projects/' + enc(name), { signal }),
        api('registry/projects/' + enc(name) + '/repositories', { signal }),
      ]);
      // A project's log is for its people; others, of a public project,
      // see none.
      const events = RANK[project.role] ? await api('registry/events?project=' + enc(name) + '&limit=100', { signal }) : null;
      return { info, project, repos, events };
    }
    case 'regrepo': {
      const repo = rest[0] || '';
      const [project, detail] = await Promise.all([
        api('registry/projects/' + enc(repo.split('/')[0]), { signal }),
        api('registry/repository?name=' + enc(repo), { signal }),
      ]);
      return { info, project, repo, detail };
    }
    case 'regartifact': {
      const [repo, ref] = [rest[0] || '', rest[1] || ''];
      const [project, artifact] = await Promise.all([
        api('registry/projects/' + enc(repo.split('/')[0]), { signal }),
        api('registry/artifact?repo=' + enc(repo) + '&ref=' + enc(ref), { signal }),
      ]);
      // An image that was scanned, or may be, has its report.
      const vulns = artifact.kind === 'image' && artifact.scan
        ? await api('registry/vulnerabilities?repo=' + enc(repo) + '&digest=' + enc(artifact.digest), { signal }).catch(() => null) : null;
      return { info, project, repo, artifact, vulns };
    }
    case 'regjobs': {
      const [jobs, scanner] = await Promise.all([api('registry/jobs?limit=100', { signal }),
        info.scanner && info.admin ? api('registry/scanner', { signal }).catch(e => ({ configured: true, problem: e.message })) : null]);
      return { info, jobs, scanner };
    }
    case 'regsources':
      return { info, sources: await api('registry/sources', { signal }) };
    case 'regreplication': {
      const [rules, sources, projects, jobs] = await Promise.all([api('registry/rules', { signal }), api('registry/sources', { signal }),
        api('registry/projects', { signal }), api('registry/jobs?limit=100', { signal })]);
      return { info, rules, sources, projects, jobs };
    }
    case 'robots':
      return { info, robots: await api('registry/robots', { signal }) };
    case 'regrunning':
      return { info, running: await api('registry/running-vulnerabilities', { signal }) };
  }
  return { info };
}

const RANK = { viewer: 1, operator: 2, admin: 3 };

export function shortDigest(d) {
  return String(d || '').replace(/^sha256:/, '').slice(0, 12);
}

// globMatch matches a tag against a pattern as the registry does (Go's
// path.Match): * is any run of characters, ? one, [...] one of a set.
export function globMatch(pattern, s) {
  const esc = c => c.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  let re = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '\\' && i + 1 < pattern.length) re += esc(pattern[++i]);
    else if (c === '[') {
      const j = pattern.indexOf(']', i + 2);
      if (j < 0) return false;
      let set = pattern.slice(i + 1, j);
      const not = set.startsWith('^');
      if (not) set = set.slice(1);
      re += '[' + (not ? '^' : '') + set.replace(/[\\\]^]/g, '\\$&') + ']';
      i = j;
    } else re += esc(c);
  }
  try {
    return new RegExp(re + '$').test(s);
  } catch {
    return false;
  }
}

// immutable tells whether a tag stays where it is in its project.
function immutable(project, tag) {
  return ((project && project.immutable) || []).some(p => globMatch(p, tag));
}

const GIB = 1024 * 1024 * 1024;

// host is where people push and pull.
function host(info) {
  return (info && info.public) || '<registry>';
}

// commitLink makes the commit an image was built from a link, from its
// OCI labels: the repository's address and the revision.
export function commitLink(labels) {
  const src = labels && labels['org.opencontainers.image.source'];
  const rev = labels && labels['org.opencontainers.image.revision'];
  if (!src || !rev || !/^https:\/\//.test(src) || !/^[0-9a-f]{7,40}$/i.test(rev)) return null;
  return src.replace(/\.git$/, '').replace(/\/$/, '') + '/commit/' + rev;
}

export function renderRegistry(view, data, ui) {
  switch (view) {
    case 'registry': return projectsPage(data, ui);
    case 'regproject': return projectPage(data, ui);
    case 'regrepo': return repositoryPage(data, ui);
    case 'regartifact': return artifactPage(data, ui);
    case 'regjobs': return jobsPage(data, ui);
    case 'regsources': return sourcesPage(data, ui);
    case 'regreplication': return replicationPage(data, ui);
    case 'robots': return robotsPage(data, ui);
    case 'regrunning': return runningPage(data, ui);
  }
  return null;
}

// ---------------------------------------------------------------- shared bits

function command(ui, text) {
  const { h, t, button, copyText } = ui;
  return h('div', { class: 'reg-command' }, h('code', { class: 'mono' }, text), button(t('copy'), () => copyText(text)));
}

// problem says what is wrong with the registry: that it was not reached,
// or, to its admins, that its metadata cannot be written.
function problem(ui, info) {
  if (info && info.problem) return ui.h('div', { class: 'banner' }, '⚠ ', ui.t('reg.unreachable'));
  if (info && info.status && info.status.problem) return ui.h('div', { class: 'banner' }, '⚠ ', ui.t('reg.storeProblem', info.status.problem));
  return null;
}

function kindPill(ui, kind) {
  return ui.h('span', { class: 'label-chip reg-kind reg-kind-' + kind }, ui.t('reg.kind.' + kind));
}

function accessPill(ui, p) {
  return ui.pill(ui.t(p.public ? 'reg.public' : 'reg.private'), p.public ? 'warn' : 'ok');
}

function crumbs(ui, items) {
  const { h } = ui;
  return h('div', { class: 'reg-crumbs' }, items.map((it, i) => [i ? h('span', { class: 'muted' }, ' › ') : null,
    it.href ? h('a', { href: it.href }, it.label) : h('strong', null, it.label)]));
}

function role(data) {
  return RANK[(data.project && data.project.role) || ''] || 0;
}

async function act(ui, fn, done) {
  try {
    await fn();
    if (done) ui.toast(done);
    ui.refresh();
  } catch (e) {
    ui.toast(e.message, true);
  }
}

// ---------------------------------------------------------------- projects

function projectsPage(data, ui) {
  const { h, t, button, bytes, age, emptyState, routeHash } = ui;
  const admin = data.info && data.info.admin;
  const words = ui.words();
  const rows = (data.projects || []).filter(p => ui.matches(words, [p.name, p.description]));
  const head = ui.panel(null, h('div', { class: 'issue' },
    h('div', { class: 'what' },
      h('div', { class: 'detail' }, t('reg.hint', host(data.info))),
      admin && data.info.status ? h('div', { class: 'detail' }, t('reg.status', data.info.status.projects, data.info.status.repositories,
        data.info.status.artifacts, bytes(data.info.status.size))) : null),
    admin ? h('div', { class: 'actions' }, button('+ ' + t('reg.newProject'), () => projectDialog(ui, null, data.info))) : null));
  if (!rows.length) return [problem(ui, data.info), head, emptyState(t(data.projects && data.projects.length ? 'noMatch' : 'reg.noProjects'))];
  return [problem(ui, data.info), head,
    h('table', null,
      h('thead', null, h('tr', null, ['project', 'access', 'yourRole', 'repositories', 'artifacts', 'size', 'created'].map(k => h('th', null, t('reg.col.' + k))))),
      h('tbody', null, rows.map(p => h('tr', null,
        h('td', null, h('a', { href: routeHash({ view: 'regproject', rest: [p.name], ns: '' }) }, h('strong', null, p.name)),
          p.description ? h('div', { class: 'muted small-text' }, p.description) : null),
        h('td', null, accessPill(ui, p)),
        h('td', null, p.role && p.role !== 'none' ? t('role.' + p.role) : h('span', { class: 'muted' }, '—')),
        h('td', null, p.repositories),
        h('td', null, p.artifacts),
        h('td', null, bytes(p.size)),
        h('td', null, age(p.created))))))];
}

function projectDialog(ui, project, info) {
  const { h, t, button, modal, dialogField, formNote, api, go } = ui;
  const editing = !!project;
  // The room a project has is the registry's admins' to give.
  const admin = !!(info && info.admin);
  const name = h('input', { type: 'text', required: !editing, disabled: editing, value: editing ? project.name : '', placeholder: 'team-a' });
  const desc = h('input', { type: 'text', value: editing ? project.description || '' : '' });
  const pub = h('input', { type: 'checkbox', checked: editing && project.public });
  const rules = h('input', { type: 'text', class: 'mono', value: editing ? (project.immutable || []).join(', ') : '', placeholder: 'v*, release-*' });
  const quota = h('input', { type: 'number', min: '0', step: 'any', disabled: !admin, placeholder: '∞',
    value: editing && project.quota ? String(Math.round(project.quota / GIB * 100) / 100) : '' });
  // Scanning on push is there when the registry has a scanner.
  const scans = !!(info && info.scanner);
  const scanOnPush = h('input', { type: 'checkbox', checked: editing && !!project.scanOnPush });
  const block = h('select', null, ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(k => h('option', { value: k, selected: editing && (project.blockSeverity || '') === k },
    k ? t('reg.sevAtLeast', t('reg.sev.' + k.toLowerCase())) : t('reg.blockNone'))));
  const allowlist = h('textarea', { class: 'mono', rows: '3', placeholder: 'CVE-2026-1234, GHSA-xxxx-xxxx-xxxx' });
  allowlist.value = editing ? (project.allowlist || []).join('\n') : '';
  const note = formNote();
  const form = h('form', {
    class: 'dialog',
    onsubmit: async e => {
      e.preventDefault();
      const body = { public: pub.checked, description: desc.value, immutable: rules.value.split(/[\s,]+/).filter(Boolean) };
      if (admin) body.quota = quota.value ? Math.round(Number(quota.value) * GIB) : 0;
      if (scans) body.scanOnPush = scanOnPush.checked;
      if (scans && editing) {
        body.blockSeverity = block.value;
        body.allowlist = allowlist.value.split(/[\s,]+/).filter(Boolean);
      }
      try {
        if (editing) {
          await api('registry/projects/' + enc(project.name), { method: 'PUT', body });
          close();
          ui.toast(t('reg.projectSaved'));
          ui.refresh();
        } else {
          body.name = name.value.trim();
          const p = await api('registry/projects', { method: 'POST', body });
          close();
          ui.toast(t('reg.projectMade', p.name));
          go({ view: 'regproject', rest: [p.name], ns: '' });
        }
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, t(editing ? 'reg.projectSettings' : 'reg.newProject')),
  dialogField(t('reg.col.project'), name, t('reg.projectNameHelp')),
  dialogField(t('reg.description'), desc),
  h('label', { class: 'check-item' }, pub, ' ', t('reg.publicHelp')),
  dialogField(t('reg.immutable'), rules, t('reg.immutableHelp')),
  dialogField(t('reg.quota'), quota, t('reg.quotaHelp')),
  scans ? h('label', { class: 'check-item' }, scanOnPush, ' ', t('reg.scanOnPushHelp')) : null,
  scans && editing ? dialogField(t('reg.blockSeverity'), block, t('reg.blockHelp')) : null,
  scans && editing ? dialogField(t('reg.allowlist'), allowlist, t('reg.allowlistHelp')) : null,
  note,
  h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()), h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  (editing ? desc : name).focus();
}

// ---------------------------------------------------------------- a project

function projectPage(data, ui) {
  const { h, t, button, bytes, age, emptyState, routeHash, ask, api } = ui;
  const p = data.project;
  const mine = role(data);
  const admin = data.info && data.info.admin;
  const words = ui.words();
  const repos = (data.repos || []).filter(r => ui.matches(words, [r.name]));
  const reg = host(data.info);
  const actions = [
    mine >= RANK.admin ? button(t('reg.projectSettings'), () => projectDialog(ui, p, data.info)) : null,
    admin ? button(t('reg.deleteProject'), async () => {
      const ok = await ask({ title: t('reg.deleteProject'), message: t('reg.deleteProjectConfirm', p.name), confirm: t('reg.deleteProject'), danger: true });
      if (!ok) return;
      try {
        await api('registry/projects/' + enc(p.name), { method: 'DELETE' });
        ui.toast(t('reg.projectDeleted', p.name));
        ui.go({ view: 'registry', rest: [], ns: '' });
      } catch (e) {
        ui.toast(e.message, true);
      }
    }, 'danger') : null,
  ];
  const head = ui.panel(null, [
    h('div', { class: 'issue' },
      h('div', { class: 'what' },
        crumbs(ui, [{ label: t('registry'), href: routeHash({ view: 'registry', rest: [], ns: '' }) }, { label: p.name }]),
        h('div', { class: 'detail' }, accessPill(ui, p), ' ', p.description || '',
          ' · ', t('reg.counts', p.repositories, p.artifacts, bytes(p.size)),
          p.role && p.role !== 'none' ? ' · ' + t('reg.yourRole', t('role.' + p.role)) : ''),
        p.quota ? h('div', { class: 'reg-quota' }, h('span', { class: 'muted' }, t('reg.quotaShort') + ' '),
          t('reg.quotaUse', bytes(p.size), bytes(p.quota), Math.min(100, Math.round(p.size / p.quota * 100))),
          h('div', { class: p.size / p.quota > 0.9 ? 'bar full' : p.size / p.quota > 0.75 ? 'bar hot' : 'bar' },
            h('span', { style: { width: Math.min(100, p.size / p.quota * 100) + '%' } }))) : null,
        p.immutable && p.immutable.length ? h('div', { class: 'detail' }, h('span', { class: 'muted' }, t('reg.immutable') + ': '),
          p.immutable.map(x => h('span', { class: 'label-chip reg-tag' }, '🔒 ', x))) : null,
        p.scanOnPush && data.info && data.info.scanner ? h('div', { class: 'detail muted' }, t('reg.scansOnPush')) : null,
        p.blockSeverity ? h('div', { class: 'detail status-warn' }, t('reg.blocksPulls', t('reg.sev.' + p.blockSeverity.toLowerCase())),
          p.allowlist && p.allowlist.length ? ' ' + t('reg.allowedCount', p.allowlist.length) : '') : null),
      h('div', { class: 'actions' }, actions)),
    h('div', { class: 'reg-commands' },
      command(ui, 'docker login ' + reg),
      command(ui, 'docker push ' + reg + '/' + p.name + '/<repository>:<tag>')),
  ]);
  const table = repos.length ? h('table', null,
    h('thead', null, h('tr', null, ['repository', 'artifacts', 'tags', 'size', 'updated', 'pulls'].map(k => h('th', null, t('reg.col.' + k))))),
    h('tbody', null, repos.map(r => h('tr', null,
      h('td', null, h('a', { href: routeHash({ view: 'regrepo', rest: [r.name], ns: '' }) }, h('strong', null, r.name.slice(p.name.length + 1)))),
      h('td', null, r.artifacts), h('td', null, r.tags), h('td', null, bytes(r.size)), h('td', null, age(r.updated)), h('td', null, r.pulls)))))
    : emptyState(t(data.repos && data.repos.length ? 'noMatch' : 'reg.noRepositories'));
  return [problem(ui, data.info), head, table, retentionPanel(ui, data), data.events ? eventsPanel(ui, data.events) : null];
}

function eventsPanel(ui, events) {
  const { h, t, age, mono } = ui;
  if (!events.length) return null;
  // A project's own changes say whether it became public or private.
  const detail = d => (d === 'public' || d === 'private' ? t('reg.' + d) : d || '');
  return ui.panel(t('reg.events'), h('table', { class: 'flat' },
    h('thead', null, h('tr', null, ['time', 'user', 'action', 'repository', 'what'].map(k => h('th', null, t('reg.col.' + k))))),
    h('tbody', null, events.map(e => h('tr', null,
      h('td', null, age(e.time)), h('td', null, e.user || h('span', { class: 'muted' }, '—')),
      h('td', null, t('reg.action.' + e.action) === 'reg.action.' + e.action ? e.action : t('reg.action.' + e.action)),
      h('td', null, e.repo || '—'),
      h('td', null, e.tag ? mono(':' + e.tag) : e.digest ? mono('@' + shortDigest(e.digest)) : detail(e.detail)))))), 'reg-events');
}

// ---------------------------------------------------------------- a repository

function platformText(a) {
  if (a.platform) return a.platform.os + '/' + a.platform.architecture + (a.platform.variant ? '/' + a.platform.variant : '');
  const ps = (a.manifests || []).map(m => m.platform).filter(Boolean).map(p => p.os + '/' + p.architecture + (p.variant ? '/' + p.variant : ''));
  return ps.join(', ');
}

function repositoryPage(data, ui) {
  const { h, t, button, bytes, age, emptyState, routeHash, ask, api, mono, copyText } = ui;
  const repo = data.repo;
  const project = repo.split('/')[0];
  const mine = role(data);
  const reg = host(data.info);
  const words = ui.words();
  const all = (data.detail && data.detail.artifacts) || [];
  const arts = all.filter(a => ui.matches(words, [a.digest, a.kind, platformText(a)].concat(a.tags)));
  const scans = !!(data.info && data.info.scanner) || all.some(a => a.scan);
  const canScan = !!(data.info && data.info.scanner) && mine >= RANK.operator;
  const fixed = a => a.tags.some(tag => immutable(data.project, tag));
  const tagChip = (a, tag) => immutable(data.project, tag) ? h('span', { class: 'label-chip reg-tag', title: t('reg.immutableTag') }, '🔒 ', tag)
    : h('span', { class: 'label-chip reg-tag' }, tag,
    mine >= RANK.operator ? h('button', {
      type: 'button', class: 'chip-x', title: t('reg.removeTag', tag),
      onclick: async () => {
        if (!(await ask({ title: t('reg.removeTag', tag), message: t('reg.removeTagConfirm', repo + ':' + tag), confirm: t('reg.removeTagShort'), danger: true }))) return;
        act(ui, () => api('registry/tag?repo=' + enc(repo) + '&tag=' + enc(tag), { method: 'DELETE' }), t('reg.tagRemoved', tag));
      },
    }, '✕') : null);
  const addTag = a => tagDialog(ui, repo, a.digest);
  const del = async a => {
    const what = a.tags.length ? repo + ':' + a.tags.join(', ') : repo + '@' + shortDigest(a.digest);
    if (!(await ask({ title: t('reg.deleteArtifact'), message: t('reg.deleteArtifactConfirm', what), confirm: t('reg.deleteArtifact'), danger: true }))) return;
    act(ui, () => api('registry/artifact?repo=' + enc(repo) + '&digest=' + enc(a.digest), { method: 'DELETE' }), t('reg.artifactDeleted'));
  };
  const head = ui.panel(null, [
    h('div', { class: 'issue' },
      h('div', { class: 'what' },
        crumbs(ui, [{ label: t('registry'), href: routeHash({ view: 'registry', rest: [], ns: '' }) },
          { label: project, href: routeHash({ view: 'regproject', rest: [project], ns: '' }) }, { label: repo.slice(project.length + 1) }]),
        data.detail && data.detail.repository ? h('div', { class: 'detail' },
          t('reg.repoCounts', data.detail.repository.artifacts, data.detail.repository.tags, bytes(data.detail.repository.size), data.detail.repository.pulls)) : null),
      mine >= RANK.operator ? h('div', { class: 'actions' }, button(t('reg.deleteRepository'), async () => {
        if (!(await ask({ title: t('reg.deleteRepository'), message: t('reg.deleteRepositoryConfirm', repo), confirm: t('reg.deleteRepository'), danger: true }))) return;
        try {
          await api('registry/repository?name=' + enc(repo), { method: 'DELETE' });
          ui.toast(t('reg.repositoryDeleted', repo));
          ui.go({ view: 'regproject', rest: [project], ns: '' });
        } catch (e) {
          ui.toast(e.message, true);
        }
      }, 'danger')) : null),
    h('div', { class: 'reg-commands' }, command(ui, 'docker pull ' + reg + '/' + repo + ':<tag>')),
  ]);
  if (!arts.length) return [problem(ui, data.info), head, emptyState(t(all.length ? 'noMatch' : 'reg.noArtifacts'))];
  return [problem(ui, data.info), head,
    h('table', null,
      h('thead', null, h('tr', null, ['artifact', 'tags', 'kind', 'platform'].concat(scans ? ['vulns'] : [], ['size', 'pushed', 'lastPull', 'pulls'])
        .map(k => h('th', null, t('reg.col.' + k))), h('th'))),
      h('tbody', null, arts.map(a => h('tr', null,
        h('td', null, h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [repo, a.digest], ns: '' }), title: a.digest }, shortDigest(a.digest)),
          a.referrers ? h('span', { class: 'muted small-text', title: t('reg.referrersHelp') }, ' · ' + t('reg.referrerCount', a.referrers)) : null),
        h('td', null, a.tags.length ? a.tags.map(tag => tagChip(a, tag)) : h('span', { class: 'muted' }, t('reg.untagged'))),
        h('td', null, kindPill(ui, a.kind)),
        h('td', null, platformText(a) || '—'),
        scans ? h('td', null, sevBar(ui, a.scan) || h('span', { class: 'muted' }, '—')) : null,
        h('td', null, bytes(a.total)),
        h('td', null, age(a.pushed), a.pushedBy ? h('div', { class: 'muted small-text' }, a.pushedBy) : null),
        h('td', null, a.lastPull ? age(a.lastPull) : h('span', { class: 'muted' }, t('reg.never'))),
        h('td', null, a.pulls),
        h('td', { class: 'actions-cell' }, h('div', { class: 'actions' },
          button(t('reg.copyPull'), () => copyText('docker pull ' + reg + '/' + repo + (a.tags.length ? ':' + a.tags[0] : '@' + a.digest))),
          mine >= RANK.operator ? button('+ ' + t('reg.tag'), () => addTag(a)) : null,
          canScan && a.scan ? scanButton(ui, repo, a) : null,
          mine >= RANK.operator && !fixed(a) ? button(t('reg.deleteArtifact'), () => del(a), 'danger') : null)))))),
    h('div', { class: 'more-note' }, t('reg.deleteNote'))];
}

function tagDialog(ui, repo, digest) {
  const { h, t, button, modal, dialogField, formNote, api } = ui;
  const tag = h('input', { type: 'text', required: true, placeholder: 'stable' });
  const note = formNote();
  const form = h('form', {
    class: 'dialog',
    onsubmit: async e => {
      e.preventDefault();
      try {
        await api('registry/tag?repo=' + enc(repo) + '&tag=' + enc(tag.value.trim()), { method: 'PUT', body: { digest } });
        close();
        ui.toast(t('reg.tagged', tag.value.trim()));
        ui.refresh();
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, t('reg.addTag')), h('p', { class: 'muted mono' }, repo + '@' + shortDigest(digest)),
  dialogField(t('reg.tag'), tag, t('reg.tagHelp')), note,
  h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()), h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  tag.focus();
}

// ---------------------------------------------------------------- an artifact

function artifactPage(data, ui) {
  const { h, t, bytes, age, routeHash, mono, copyText, button } = ui;
  const a = data.artifact;
  const repo = data.repo;
  const canScan = !!(data.info && data.info.scanner) && role(data) >= RANK.operator && !!a.scan;
  const project = repo.split('/')[0];
  const reg = host(data.info);
  const kv = (k, v) => v == null || v === '' ? null : h('div', { class: 'kv-row' }, h('span', { class: 'kv-key' }, t(k)), h('span', { class: 'kv-value' }, v));
  const labels = (a.config && a.config.Labels) || a.labels || null;
  const commit = commitLink(labels);
  const summary = ui.panel(null, h('div', { class: 'reg-body' },
    crumbs(ui, [{ label: t('registry'), href: routeHash({ view: 'registry', rest: [], ns: '' }) },
      { label: project, href: routeHash({ view: 'regproject', rest: [project], ns: '' }) },
      { label: repo.slice(project.length + 1), href: routeHash({ view: 'regrepo', rest: [repo], ns: '' }) },
      { label: a.tags && a.tags.length ? a.tags.join(', ') : shortDigest(a.digest) }]),
    h('div', { class: 'kv' },
      kv('reg.digest', h('span', null, mono(a.digest), ' ', button(t('copy'), () => copyText(a.digest)))),
      kv('reg.col.kind', kindPill(ui, a.kind)),
      kv('reg.mediaType', mono(a.mediaType)),
      kv('reg.artifactType', a.artifactType ? mono(a.artifactType) : null),
      kv('reg.col.platform', platformText(a) || null),
      kv('reg.col.size', bytes(a.total) + ' (' + t('reg.manifestSize', bytes(a.size)) + ')'),
      kv('reg.created', a.created ? age(a.created) : null),
      kv('reg.col.pushed', h('span', null, age(a.pushed), a.pushedBy ? ' · ' + a.pushedBy : '')),
      kv('reg.col.pulls', a.pulls + (a.lastPull ? ' · ' + t('reg.lastPullAgo', ui.ago(a.lastPull)) : '')),
      kv('reg.commit', commit ? h('a', { href: commit, target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, labels['org.opencontainers.image.revision'].slice(0, 12)) : null),
      kv('reg.subject', a.subject ? h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [repo, a.subject], ns: '' }) }, shortDigest(a.subject)) : null),
      kv('reg.col.vulns', a.scan ? h('span', null, sevBar(ui, a.scan), canScan ? [' ', scanButton(ui, repo, a)] : null) : null)),
    h('div', { class: 'reg-commands' }, command(ui, 'docker pull ' + reg + '/' + repo + '@' + a.digest))));
  const parts = [problem(ui, data.info), summary];
  if (a.children && a.children.length) {
    const scans = a.children.some(c => c.scan);
    parts.push(ui.panel(t('reg.children'), h('table', { class: 'flat' },
      h('thead', null, h('tr', null, ['platform', 'artifact', 'size'].concat(scans ? ['vulns'] : []).map(k => h('th', null, t('reg.col.' + k))))),
      h('tbody', null, a.children.map(c => h('tr', null, h('td', null, platformText(c) || '—'),
        h('td', null, h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [repo, c.digest], ns: '' }) }, shortDigest(c.digest))),
        h('td', null, bytes(c.total)),
        scans ? h('td', null, sevBar(ui, c.scan) || '—') : null))))));
  }
  if (data.vulns) parts.push(vulnPanel(ui, data));
  if (labels && Object.keys(labels).length) {
    parts.push(ui.panel(t('reg.labels'), h('div', { class: 'kv reg-body' }, Object.keys(labels).sort().map(k =>
      h('div', { class: 'kv-row' }, h('span', { class: 'kv-key mono' }, k), h('span', { class: 'kv-value mono' }, labels[k]))))));
  }
  if (a.layers && a.layers.length) {
    const history = ((a.config && a.config.History) || []).filter(s => !s.empty_layer);
    parts.push(ui.panel(t('reg.layers'), h('table', { class: 'flat' },
      h('thead', null, h('tr', null, h('th', null, '#'), ['size', 'step'].map(k => h('th', null, t('reg.col.' + k))), h('th', null, t('reg.digest')))),
      h('tbody', null, a.layers.map((l, i) => h('tr', null, h('td', null, i + 1), h('td', null, bytes(l.size)),
        h('td', { class: 'reg-step' }, history[i] ? mono(history[i].created_by || '') : h('span', { class: 'muted' }, l.mediaType)),
        h('td', null, mono(shortDigest(l.digest)))))))));
  }
  if (a.referrerList && a.referrerList.length) {
    parts.push(ui.panel(t('reg.referrers'), h('table', { class: 'flat' },
      h('thead', null, h('tr', null, ['kind', 'artifact', 'pushed'].map(k => h('th', null, t('reg.col.' + k))))),
      h('tbody', null, a.referrerList.map(r => h('tr', null, h('td', null, kindPill(ui, r.kind)),
        h('td', null, h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [repo, r.digest], ns: '' }), title: r.artifactType || '' }, shortDigest(r.digest))),
        h('td', null, age(r.pushed))))))));
  }
  if (a.manifest) {
    parts.push(h('details', { class: 'panel reg-manifest' }, h('summary', null, t('reg.manifest')),
      h('pre', { class: 'mono' }, JSON.stringify(a.manifest, null, 2))));
  }
  return parts;
}

// ---------------------------------------------------------------- retention

const KEEPS = ['latestPushed', 'latestPulled', 'pushedWithin', 'pulledWithin', 'always'];

// The template people start from: the 5 latest, and what is newer than
// 180 days.
const TEMPLATE = [
  { repositories: '**', tags: '**', untagged: true, keep: 'latestPushed', count: 5 },
  { repositories: '**', tags: '**', untagged: true, keep: 'pushedWithin', days: 180 },
];

// ruleText says a rule in words.
function ruleText(ui, r) {
  const { t } = ui;
  const repos = !r.repositories || r.repositories === '**' ? t('reg.allRepos') : r.repositories;
  const tags = r.tags === '**' ? '*' : r.tags;
  const picks = !r.tags ? t('reg.rulePicksUntagged', repos) : r.untagged ? t('reg.rulePicksBoth', repos, tags) : t('reg.rulePicks', repos, tags);
  return picks + ' → ' + t('reg.keep.' + r.keep, r.keep.startsWith('latest') ? r.count : r.days);
}

function retentionPanel(ui, data) {
  const { h, t, button } = ui;
  const p = data.project;
  const rules = p.retention || [];
  const mine = role(data);
  if (!rules.length && mine < RANK.admin) return null;
  const run = async dryRun => {
    if (!dryRun && !(await ui.ask({ title: t('reg.retentionRun'), message: t('reg.retentionConfirm', p.name), confirm: t('reg.retentionRun'), danger: true }))) return;
    try {
      const j = await ui.api('registry/jobs', { method: 'POST', body: { kind: 'retention', project: p.name, dryRun } });
      jobDialog(ui, j.id, t('reg.retentionResult', p.name));
    } catch (e) {
      ui.toast(e.message, true);
    }
  };
  return ui.panel(t('reg.retention'), h('div', { class: 'reg-body' },
    h('div', { class: 'muted small-text' }, t('reg.retentionHint')),
    rules.length ? h('ul', { class: 'reg-rules' }, rules.map(r => h('li', null, ruleText(ui, r)))) : h('div', { class: 'muted' }, t('reg.noRetention')),
    mine >= RANK.admin ? h('div', { class: 'actions' },
      button(t('reg.editRetention'), () => retentionDialog(ui, p)),
      rules.length ? button(t('reg.retentionDry'), () => run(true)) : null,
      rules.length ? button(t('reg.retentionRun'), () => run(false), 'danger') : null) : null), 'reg-events');
}

function retentionDialog(ui, p) {
  const { h, t, button, modal, formNote, api } = ui;
  const list = h('div', { class: 'reg-rule-list' });
  const rows = [];
  const addRow = r => {
    const repos = h('input', { type: 'text', class: 'mono', value: r.repositories || '**', 'aria-label': t('reg.rule.repos') });
    const tags = h('input', { type: 'text', class: 'mono', value: r.tags == null ? '**' : r.tags, 'aria-label': t('reg.rule.tags') });
    const untagged = h('input', { type: 'checkbox', checked: !!r.untagged });
    const keep = h('select', { 'aria-label': t('reg.rule.keep') }, KEEPS.map(k => h('option', { value: k, selected: k === r.keep }, t('reg.keepOpt.' + k))));
    const n = h('input', { type: 'number', min: '1', step: '1', value: String(r.keep && r.keep.startsWith('latest') ? r.count || 5 : r.days || 30) });
    const sync = () => { n.hidden = keep.value === 'always'; };
    keep.addEventListener('change', sync);
    sync();
    const row = h('div', { class: 'reg-rule' },
      h('label', { class: 'field' }, h('span', null, t('reg.rule.repos')), repos),
      h('label', { class: 'field' }, h('span', null, t('reg.rule.tags')), tags),
      h('label', { class: 'check-item' }, untagged, ' ', t('reg.rule.untagged')),
      h('label', { class: 'field' }, h('span', null, t('reg.rule.keep')), h('div', { class: 'reg-keep' }, keep, n)),
      button('✕', () => { row.remove(); rows.splice(rows.indexOf(item), 1); }, 'small'));
    const item = {
      row,
      value: () => {
        const v = { repositories: repos.value.trim(), tags: tags.value.trim(), untagged: untagged.checked, keep: keep.value };
        if (v.keep.startsWith('latest')) v.count = Number(n.value);
        else if (v.keep !== 'always') v.days = Number(n.value);
        return v;
      },
    };
    rows.push(item);
    list.append(row);
  };
  (p.retention || []).forEach(addRow);
  const note = formNote();
  const form = h('form', {
    class: 'dialog wide',
    onsubmit: async e => {
      e.preventDefault();
      try {
        await api('registry/projects/' + enc(p.name), { method: 'PUT', body: { retention: rows.map(x => x.value()) } });
        close();
        ui.toast(t('reg.retentionSaved'));
        ui.refresh();
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, t('reg.retention') + ' · ' + p.name),
  h('p', { class: 'muted small-text' }, t('reg.rulesHelp')),
  list,
  h('div', { class: 'actions' },
    button(t('reg.addRule'), () => addRow({ repositories: '**', tags: '**', keep: 'latestPushed', count: 10 })),
    button(t('reg.template'), () => {
      rows.splice(0).forEach(x => x.row.remove());
      TEMPLATE.forEach(addRow);
    })),
  note,
  h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()), h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
}

// jobDialog waits for a job and shows what it did, or would do.
function jobDialog(ui, id, title) {
  const { h, t, modal } = ui;
  const body = h('div', null, h('p', { class: 'muted' }, t('reg.waitJob')));
  const box = h('div', { class: 'dialog wide' }, h('h2', null, title), body,
    h('div', { class: 'dialog-actions' }, h('button', { type: 'button', class: 'btn primary', onclick: () => close() }, t('done'))));
  const close = modal(box);
  let tries = 0;
  const poll = async () => {
    if (!box.isConnected) return;
    let j;
    try {
      j = await ui.api('registry/jobs/' + enc(id));
    } catch (e) {
      body.replaceChildren(h('p', { class: 'status-bad' }, e.message));
      return;
    }
    if (j.status === 'running' && ++tries < 3600) {
      body.replaceChildren(h('p', { class: 'muted' }, progressText(ui, j.progress)));
      setTimeout(poll, 1000);
      return;
    }
    const r = j.report || {};
    const removed = r.removed || [];
    const items = r.items || [];
    const failures = r.failures || [];
    // A DOM node takes null for text; what is not there is left out.
    body.replaceChildren(...[
      j.error ? h('p', { class: 'status-bad' }, j.error) : h('p', null, jobSummary(ui, j)),
      r.unknown && r.unknown.length ? h('p', { class: 'muted small-text' }, t('reg.retentionUnknown', r.unknown.join(', '))) : null,
      removed.length ? h('table', { class: 'flat' },
        h('thead', null, h('tr', null, ['repository', 'artifact', 'tags', 'pushed'].map(k => h('th', null, t('reg.col.' + k))))),
        h('tbody', null, removed.map(x => h('tr', null, h('td', null, x.repo), h('td', null, ui.mono(shortDigest(x.digest))),
          h('td', null, x.tags && x.tags.length ? x.tags.join(', ') : h('span', { class: 'muted' }, t('reg.untagged'))), h('td', null, ui.age(x.pushed))))))
        : j.kind === 'retention' && j.status === 'done' ? h('p', { class: 'muted' }, t('reg.removedNone')) : null,
      items.length ? h('table', { class: 'flat' },
        h('thead', null, h('tr', null, ['from', 'into', 'status', 'what'].map(k => h('th', null, t('reg.col.' + k))))),
        h('tbody', null, items.map(x => h('tr', { class: x.result === 'failed' ? 'problem' : null }, h('td', null, ui.mono(x.from)), h('td', null, ui.mono(x.to)),
          h('td', null, t('reg.item.' + x.result)), h('td', null, x.error || (x.digest ? ui.mono(shortDigest(x.digest)) : ''))))))
        : j.kind === 'replication' && j.status === 'done' ? h('p', { class: 'muted' }, t('reg.allPresent')) : null,
      r.dbError ? h('p', { class: 'status-bad small-text' }, t('reg.dbNotUpdatedWhy', r.dbError)) : null,
      failures.length ? h('table', { class: 'flat' },
        h('thead', null, h('tr', null, ['repository', 'artifact', 'what'].map(k => h('th', null, t('reg.col.' + k))))),
        h('tbody', null, failures.map(x => h('tr', { class: 'problem' }, h('td', null, x.repo), h('td', null, ui.mono(shortDigest(x.digest))),
          h('td', null, x.error))))) : null].filter(Boolean));
    ui.refresh();
  };
  poll();
}

// ---------------------------------------------------------------- replication

// progressText says how far a running job got.
function progressText(ui, p) {
  if (p && p.waiting) return ui.t('reg.queued');
  return p ? ui.t('reg.progress', p.done, p.total, ui.bytes(p.bytes)) : ui.t('reg.waitJob');
}

function stopButton(ui, j) {
  return ui.button(ui.t('reg.stopJob'), async () => {
    if (!(await ui.ask({ title: ui.t('reg.stopJob'), message: ui.t('reg.stopConfirm'), confirm: ui.t('reg.stopJob'), danger: true }))) return;
    act(ui, () => ui.api('registry/jobs/' + enc(j.id), { method: 'DELETE' }), ui.t('reg.stopped'));
  }, 'danger');
}

function replicationPage(data, ui) {
  const { h, t, button, age, emptyState, mono, routeHash } = ui;
  const rules = data.rules || [];
  const sources = data.sources || [];
  const jobs = ((data.jobs && data.jobs.jobs) || []).filter(j => j.kind === 'replication');
  const words = ui.words();
  const rows = rules.filter(r => ui.matches(words, [r.name, r.sourceName, r.repositories, r.tags, r.project]));
  const run = async (r, dryRun) => {
    if (!dryRun && !(await ui.ask({ title: t('reg.runRule'), message: t('reg.runRuleConfirm', r.name, r.project), confirm: t('reg.runRule') }))) return;
    try {
      const j = await ui.api('registry/jobs', { method: 'POST', body: { kind: 'replication', rule: r.id, dryRun } });
      jobDialog(ui, j.id, r.name);
    } catch (e) {
      ui.toast(e.message, true);
    }
  };
  const head = ui.panel(null, h('div', { class: 'issue' },
    h('div', { class: 'what' }, h('div', { class: 'detail' }, t('reg.replHint')),
      sources.length ? null : h('div', { class: 'detail status-warn' }, t('reg.needSource'), ' ',
        h('a', { href: routeHash({ view: 'regsources', rest: [], ns: '' }) }, t('regsources')))),
    h('div', { class: 'actions' }, sources.length ? [button(t('reg.trivyTemplate'), () => trivyDialog(ui, data)),
      button('+ ' + t('reg.newRule'), () => ruleDialog(ui, data))] : null)));
  const table = rows.length ? h('table', null,
    h('thead', null, h('tr', null, ['name', 'from', 'into', 'cron', 'next'].map(k => h('th', null, t('reg.col.' + k))), h('th'))),
    h('tbody', null, rows.map(r => {
      const running = jobs.find(j => j.rule === r.id && j.status === 'running');
      return h('tr', null,
        h('td', null, h('strong', null, r.name)),
        h('td', null, r.sourceName, ' · ', mono(r.repositories), r.tags && r.tags !== '**' ? [' : ', mono(r.tags)] : null,
          r.within ? h('div', { class: 'muted small-text' }, t('reg.withinDays', r.within)) : null),
        h('td', null, h('a', { href: routeHash({ view: 'regproject', rest: [r.project], ns: '' }) }, r.project),
          h('div', { class: 'muted small-text' }, [r.keepPath ? t('reg.keepPath') : null, r.overwrite ? t('reg.overwrite') : null,
            r.referrers ? t('reg.withReferrers') : null, r.platforms && r.platforms.length ? r.platforms.join(', ') : null].filter(Boolean).join(' · '))),
        h('td', null, r.cron ? mono(r.cron) : h('span', { class: 'muted' }, t('reg.manual')), r.cron && !r.enabled ? [' ', ui.pill(t('reg.scheduleOff'), 'warn')] : null),
        h('td', null, r.next ? ui.until(r.next) : '—'),
        h('td', { class: 'actions-cell' }, h('div', { class: 'actions' },
          running ? [h('span', { class: 'muted small-text' }, progressText(ui, running.progress)), stopButton(ui, running)]
            : [button(t('reg.retentionDry'), () => run(r, true)), button(t('reg.runRule'), () => run(r, false))],
          button(t('edit'), () => ruleDialog(ui, data, r)),
          button(t('reg.deleteRule'), async () => {
            if (!(await ui.ask({ title: t('reg.deleteRule'), message: t('reg.deleteRuleConfirm', r.name), confirm: t('reg.deleteRule'), danger: true }))) return;
            act(ui, () => ui.api('registry/rules/' + enc(r.id), { method: 'DELETE' }), t('reg.ruleDeleted'));
          }, 'danger'))));
    }))) : emptyState(t(rules.length ? 'noMatch' : 'reg.noRules'));
  const recent = jobs.length ? ui.panel(t('reg.replRuns'), h('table', { class: 'flat' },
    h('thead', null, h('tr', null, ['name', 'by', 'started', 'took', 'status', 'what'].map(k => h('th', null, t('reg.col.' + k))))),
    h('tbody', null, jobs.slice(0, 20).map(j => h('tr', { class: j.status === 'failed' || j.alarm ? 'problem' : null },
      h('td', null, j.ruleName || '—', j.dryRun ? h('span', { class: 'muted' }, ' · ' + t('reg.dryRun')) : null),
      h('td', null, j.by === 'schedule' ? h('span', { class: 'muted' }, t('reg.bySchedule')) : j.by),
      h('td', null, age(j.started)),
      h('td', null, j.finished ? ui.duration(j.started, j.finished) : progressText(ui, j.progress)),
      h('td', null, jobState(ui, j)),
      h('td', null, j.error ? h('span', { class: 'status-bad' }, j.error) : jobSummary(ui, j)))))), 'reg-events') : null;
  return [problem(ui, data.info), head, table, recent];
}

function ruleDialog(ui, data, rule) {
  const { h, t, button, modal, dialogField, formNote, api } = ui;
  const editing = !!rule;
  const r = rule || { repositories: '', tags: '**', concurrency: 2 };
  const name = h('input', { type: 'text', required: true, value: r.name || '' });
  const source = h('select', null, (data.sources || []).map(x => h('option', { value: x.id, selected: x.id === r.source }, x.name + ' (' + t('reg.kindSrc.' + x.kind) + ')')));
  const repos = h('input', { type: 'text', class: 'mono', required: true, value: r.repositories, placeholder: 'team-a/**' });
  const tags = h('input', { type: 'text', class: 'mono', value: r.tags || '**', placeholder: '**' });
  const within = h('input', { type: 'number', min: '0', step: '1', value: r.within ? String(r.within) : '', placeholder: '∞' });
  const project = h('select', null, (data.projects || []).map(p => h('option', { value: p.name, selected: p.name === r.project }, p.name)));
  const keepPath = h('input', { type: 'checkbox', checked: !!r.keepPath });
  const overwrite = h('input', { type: 'checkbox', checked: !!r.overwrite });
  const referrers = h('input', { type: 'checkbox', checked: editing ? !!r.referrers : true });
  const platforms = h('input', { type: 'text', class: 'mono', value: (r.platforms || []).join(', '), placeholder: 'linux/amd64, linux/arm64' });
  const concurrency = h('input', { type: 'number', min: '1', max: '8', step: '1', value: String(r.concurrency || 2) });
  const bandwidth = h('input', { type: 'number', min: '0', step: '1', value: r.bandwidthKiB ? String(r.bandwidthKiB) : '', placeholder: '∞' });
  const cron = h('input', { type: 'text', class: 'mono', value: r.cron || '', placeholder: '0 * * * *' });
  const enabled = h('input', { type: 'checkbox', checked: editing ? !!r.enabled : true });
  const preview = h('div', { class: 'muted small-text' });
  // Where a repository of the source goes.
  const show = () => {
    const example = (repos.value.trim() || 'team-a/web').replace(/\/?\*\*$/, '/web').replace(/\*/g, 'web');
    const parts = example.split('/');
    const rest = keepPath.checked || parts.length < 2 ? example : parts.slice(1).join('/');
    preview.textContent = t('reg.namedAs', example, (project.value || '<project>') + '/' + rest);
  };
  [repos, project, keepPath].forEach(el => el.addEventListener(el.type === 'checkbox' || el.tagName === 'SELECT' ? 'change' : 'input', show));
  show();
  const note = formNote();
  const form = h('form', {
    class: 'dialog wide',
    onsubmit: async e => {
      e.preventDefault();
      const body = {
        name: name.value.trim(), source: source.value, repositories: repos.value.trim(), tags: tags.value.trim(),
        within: Number(within.value) || 0, project: project.value, keepPath: keepPath.checked, overwrite: overwrite.checked,
        referrers: referrers.checked, platforms: platforms.value.split(/[\s,]+/).filter(Boolean),
        concurrency: Number(concurrency.value) || 2, bandwidthKiB: Number(bandwidth.value) || 0, cron: cron.value.trim(), enabled: enabled.checked,
      };
      try {
        await api('registry/rules' + (editing ? '/' + enc(rule.id) : ''), { method: editing ? 'PUT' : 'POST', body });
        close();
        ui.toast(t('reg.ruleSaved'));
        ui.refresh();
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, editing ? rule.name : t('reg.newRule')),
  dialogField(t('reg.col.name'), name),
  dialogField(t('reg.ruleSource'), source),
  dialogField(t('reg.rule.repos'), repos, t('reg.ruleReposHelp')),
  dialogField(t('reg.rule.tags'), tags, t('reg.ruleTagsHelp')),
  dialogField(t('reg.ruleWithin'), within, t('reg.ruleWithinHelp')),
  dialogField(t('reg.ruleProject'), project),
  h('label', { class: 'check-item' }, keepPath, ' ', t('reg.keepPathHelp')),
  preview,
  h('label', { class: 'check-item' }, overwrite, ' ', t('reg.overwriteHelp')),
  h('label', { class: 'check-item' }, referrers, ' ', t('reg.referrersCopyHelp')),
  dialogField(t('reg.rulePlatforms'), platforms, t('reg.rulePlatformsHelp')),
  h('div', { class: 'reg-two' }, dialogField(t('reg.ruleConcurrency'), concurrency), dialogField(t('reg.ruleBandwidth'), bandwidth)),
  dialogField(t('reg.col.cron'), cron, t('reg.ruleCronHelp')),
  h('label', { class: 'check-item' }, enabled, ' ', t('reg.scheduleOn')),
  note,
  h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()), h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  name.focus();
}

// ---------------------------------------------------------------- jobs

// jobSummary says what a job did, from its report.
function jobSummary(ui, j) {
  const { t, bytes } = ui;
  const r = j.report || {};
  if (j.kind === 'gc' && r.started) {
    return t(r.dryRun ? 'reg.gcDrySummary' : 'reg.gcSummary', r.unlinked, r.blobs, bytes(r.freed), r.uploads, r.spared);
  }
  if (j.kind === 'verify' && r.started) {
    return t('reg.verifySummary', r.checked, bytes(r.bytes), (r.corrupt || []).length, (r.missing || []).length);
  }
  if (j.kind === 'retention' && r.started) {
    return t(r.dryRun ? 'reg.retentionDrySummary' : 'reg.retentionSummary', r.picked, r.kept, r.protected, r.deleted);
  }
  if (j.kind === 'replication' && r.started) {
    return t(r.dryRun ? 'reg.replDrySummary' : 'reg.replSummary', r.picked, r.copied, bytes(r.bytes), r.present, r.kept, r.failed);
  }
  if (j.kind === 'scan' && r.started) {
    return t('reg.scanSummary', r.scanned || 0, r.failed || 0, r.critical || 0, r.high || 0) + (r.dbError ? ' · ' + t('reg.dbNotUpdated') : '');
  }
  return j.summary || '';
}

function jobState(ui, j) {
  if (j.status === 'running') return ui.pill(ui.t('reg.state.running'), 'warn');
  if (j.status === 'failed') return ui.pill(ui.t('reg.state.failed'), 'bad');
  return j.alarm ? ui.pill(ui.t('reg.state.alarm'), 'bad') : ui.pill(ui.t('reg.state.done'), 'ok');
}

function jobsPage(data, ui) {
  const { h, t, button, age, emptyState, api, mono } = ui;
  const { jobs = [], schedules = [], zone = '' } = data.jobs || {};
  const start = (kind, dryRun) => act(ui, () => api('registry/jobs', { method: 'POST', body: { kind, dryRun } }), t('reg.jobStarted'));
  const head = ui.panel(null, h('div', { class: 'issue' },
    h('div', { class: 'what' }, h('div', { class: 'detail' }, t('reg.jobsHint', zone))),
    h('div', { class: 'actions' },
      button(t('reg.gcDry'), () => start('gc', true)),
      button(t('reg.gcNow'), async () => {
        if (await ui.ask({ title: t('reg.gcNow'), message: t('reg.gcConfirm'), confirm: t('reg.gcNow'), danger: true })) start('gc', false);
      }, 'danger'),
      button(t('reg.verifyNow'), () => start('verify', false)),
      button(t('reg.retentionAllDry'), () => start('retention', true)),
      data.scanner && data.scanner.configured ? button(t('reg.scanAll'), async () => {
        if (await ui.ask({ title: t('reg.scanAll'), message: t('reg.scanAllConfirm'), confirm: t('reg.scanAll') })) start('scan', false);
      }) : null)));
  const sched = ui.panel(t('reg.schedules'), h('table', { class: 'flat' },
    h('thead', null, h('tr', null, ['job', 'cron', 'next', 'lastRun'].map(k => h('th', null, t('reg.col.' + k))), h('th'))),
    h('tbody', null, schedules.map(sc => h('tr', null,
      h('td', null, t('reg.job.' + sc.kind)),
      h('td', null, mono(sc.cron), sc.enabled ? null : [' ', ui.pill(t('reg.scheduleOff'), 'warn')]),
      h('td', null, sc.next ? ui.until(sc.next) : '—'),
      h('td', null, sc.last ? age(sc.last) : h('span', { class: 'muted' }, t('reg.never'))),
      h('td', { class: 'actions-cell' }, button(t('edit'), () => scheduleDialog(ui, sc, zone))))))), 'reg-events');
  const history = jobs.length ? h('table', null,
    h('thead', null, h('tr', null, ['job', 'by', 'started', 'took', 'status', 'what'].map(k => h('th', null, t('reg.col.' + k))))),
    h('tbody', null, jobs.map(j => h('tr', { class: j.status === 'failed' || j.alarm ? 'problem' : null },
      h('td', null, t('reg.job.' + j.kind), j.ruleName ? h('span', { class: 'muted' }, ' · ' + j.ruleName) : j.project ? h('span', { class: 'muted' }, ' · ' + j.project) : null,
        j.dryRun ? h('span', { class: 'muted' }, ' · ' + t('reg.dryRun')) : null),
      h('td', null, j.by === 'schedule' ? h('span', { class: 'muted' }, t('reg.bySchedule')) : j.by),
      h('td', null, age(j.started)),
      h('td', null, j.finished ? ui.duration(j.started, j.finished) : progressText(ui, j.progress)),
      h('td', null, jobState(ui, j), j.status === 'running' ? [' ', stopButton(ui, j)] : null),
      h('td', null, j.error ? h('span', { class: 'status-bad' }, j.error) : [jobSummary(ui, j),
        j.alarm && j.kind === 'verify' ? h('div', { class: 'status-bad small-text' }, t('reg.verifyAlarm', ((j.report || {}).corrupt || []).length,
          ((j.report || {}).missing || []).length)) : null,
        j.alarm && j.kind === 'scan' && (j.report || {}).failed ? h('div', { class: 'status-bad small-text' },
          t('reg.scanAlarm', j.report.failed, j.report.images)) : null]))))) : emptyState(t('reg.noJobs'));
  return [problem(ui, data.info), head, scannerPanel(ui, data), sched, h('div', { class: 'reg-events' }, history)];
}

function scheduleDialog(ui, sc, zone) {
  const { h, t, button, modal, dialogField, formNote, api } = ui;
  const expr = h('input', { type: 'text', class: 'mono', required: true, value: sc.cron });
  const on = h('input', { type: 'checkbox', checked: sc.enabled });
  const note = formNote();
  const form = h('form', {
    class: 'dialog',
    onsubmit: async e => {
      e.preventDefault();
      try {
        await api('registry/schedules/' + enc(sc.kind), { method: 'PUT', body: { cron: expr.value.trim(), enabled: on.checked } });
        close();
        ui.toast(t('reg.scheduleSaved'));
        ui.refresh();
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, t('reg.editSchedule', t('reg.job.' + sc.kind))),
  dialogField(t('reg.col.cron'), expr, t('reg.cronHelp', zone)),
  h('label', { class: 'check-item' }, on, ' ', t('reg.scheduleOn')),
  note,
  h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()), h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  expr.focus();
}

// ---------------------------------------------------------------- sources

const SOURCE_KINDS = ['harbor', 'nexus', 'registry'];

function sourcesPage(data, ui) {
  const { h, t, button, age, emptyState, ask, api, mono } = ui;
  const all = data.sources || [];
  const words = ui.words();
  const rows = all.filter(x => ui.matches(words, [x.name, x.kind, x.url, x.repository, x.username]));
  const head = ui.panel(null, h('div', { class: 'issue' },
    h('div', { class: 'what' }, h('div', { class: 'detail' }, t('reg.sourcesHint'))),
    h('div', { class: 'actions' }, button('+ ' + t('reg.newSource'), () => sourceDialog(ui)))));
  if (!rows.length) return [problem(ui, data.info), head, emptyState(t(all.length ? 'noMatch' : 'reg.noSources'))];
  return [problem(ui, data.info), head,
    h('table', null,
      h('thead', null, h('tr', null, ['name', 'kind', 'url', 'username', 'created'].map(k => h('th', null, t('reg.col.' + k))), h('th'))),
      h('tbody', null, rows.map(x => h('tr', null,
        h('td', null, h('strong', null, x.name)),
        h('td', null, t('reg.kindSrc.' + x.kind)),
        h('td', null, mono(x.url), x.repository ? h('div', { class: 'muted small-text' }, t('reg.sourceRepo') + ': ' + x.repository) : null,
          x.insecure ? h('div', { class: 'status-warn small-text' }, t('reg.sourceInsecure')) : null),
        h('td', null, x.username || h('span', { class: 'muted' }, '—')),
        h('td', null, age(x.created), x.by ? h('div', { class: 'muted small-text' }, x.by) : null),
        h('td', { class: 'actions-cell' }, h('div', { class: 'actions' },
          button(t('reg.migrate'), () => migrateDialog(ui, x)),
          button(t('edit'), () => sourceDialog(ui, x)),
          button(t('reg.deleteSource'), async () => {
            if (!(await ask({ title: t('reg.deleteSource'), message: t('reg.deleteSourceConfirm', x.name), confirm: t('reg.deleteSource'), danger: true }))) return;
            act(ui, () => api('registry/sources/' + enc(x.id), { method: 'DELETE' }), t('reg.sourceDeleted'));
          }, 'danger'))))))),
  ];
}

function sourceDialog(ui, src) {
  const { h, t, button, modal, dialogField, formNote, api } = ui;
  const editing = !!src;
  const name = h('input', { type: 'text', required: true, value: editing ? src.name : '', placeholder: 'Harbor' });
  const kind = h('select', null, SOURCE_KINDS.map(k => h('option', { value: k, selected: editing ? src.kind === k : k === 'harbor' }, t('reg.kindSrc.' + k))));
  const url = h('input', { type: 'url', required: true, class: 'mono', value: editing ? src.url : '', placeholder: 'https://harbor.example.org' });
  const repo = h('input', { type: 'text', class: 'mono', value: editing ? src.repository || '' : '', placeholder: 'docker-hosted' });
  const user = h('input', { type: 'text', autocomplete: 'off', value: editing ? src.username || '' : '' });
  const pass = h('input', { type: 'password', autocomplete: 'new-password', placeholder: editing && src.hasSecret ? t('reg.sourcePassKeep') : '' });
  const ca = h('textarea', { rows: '3', class: 'mono', placeholder: '-----BEGIN CERTIFICATE-----' });
  ca.value = editing ? src.ca || '' : '';
  const insecure = h('input', { type: 'checkbox', checked: editing && src.insecure });
  const repoField = dialogField(t('reg.sourceRepo'), repo, t('reg.sourceRepoHelp'));
  const sync = () => { repoField.hidden = kind.value !== 'nexus'; };
  kind.addEventListener('change', sync);
  sync();
  const note = formNote();
  // A password left empty when editing stays as it was.
  const body = () => {
    const b = { name: name.value.trim(), kind: kind.value, url: url.value.trim(), repository: repo.value.trim(), username: user.value.trim(),
      ca: ca.value.trim(), insecure: insecure.checked };
    if (!editing || pass.value) b.password = pass.value;
    return b;
  };
  const test = async () => {
    note.say(t('reg.testing'));
    try {
      const b = body();
      if (editing) b.id = src.id;
      const r = await api('registry/sources/test', { method: 'POST', body: b });
      if (r.ok) note.say('✓ ' + t('reg.testOK', r.seconds.toFixed(1), r.projects && r.projects.length ? t('reg.testProjects', r.projects.length) : ''), 'ok');
      else note.say(r.error, 'bad');
    } catch (e) {
      note.say(e.message, 'bad');
    }
  };
  const form = h('form', {
    class: 'dialog wide',
    onsubmit: async e => {
      e.preventDefault();
      try {
        await api('registry/sources' + (editing ? '/' + enc(src.id) : ''), { method: editing ? 'PUT' : 'POST', body: body() });
        close();
        ui.toast(t('reg.sourceSaved'));
        ui.refresh();
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, editing ? src.name : t('reg.newSource')),
  dialogField(t('reg.col.name'), name),
  dialogField(t('reg.sourceKind'), kind),
  dialogField(t('reg.col.url'), url, t('reg.sourceURLHelp')),
  repoField,
  dialogField(t('reg.sourceUser'), user),
  dialogField(t('reg.sourcePass'), pass),
  dialogField(t('reg.sourceCA'), ca, t('reg.sourceCAHelp')),
  h('label', { class: 'check-item' }, insecure, ' ', t('reg.sourceInsecure')),
  note,
  h('div', { class: 'dialog-actions' }, button(t('reg.testSource'), test), button(t('cancel'), () => close()),
    h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  name.focus();
}

// migrateDialog moves projects of a source here: they are made, and a
// rule copies each, now, and every hour while people move over if asked.
async function migrateDialog(ui, src) {
  const { h, t, button, modal, api, routeHash } = ui;
  const body = h('div', null, h('p', { class: 'muted' }, t('reg.loadingProjects')));
  const box = h('div', { class: 'dialog wide' }, h('h2', null, t('reg.migrateTitle', src.name)), body);
  const close = modal(box);
  let theirs;
  let ours;
  try {
    [theirs, ours] = await Promise.all([api('registry/sources/' + enc(src.id) + '/projects'), api('registry/projects')]);
  } catch (e) {
    body.replaceChildren(h('p', { class: 'status-bad' }, e.message), h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close())));
    return;
  }
  const here = new Set(ours.map(p => p.name));
  const picks = theirs.map(p => ({ p, input: h('input', { type: 'checkbox', checked: !here.has(p.name), 'aria-label': p.name }) }));
  const sync = h('input', { type: 'checkbox' });
  const note = ui.formNote();
  const runs = out => {
    const rows = out.map(m => ({ m, status: h('td', null, m.error ? h('span', { class: 'status-bad' }, m.error) : t('reg.waitJob')) }));
    body.replaceChildren(
      h('table', { class: 'flat' },
        h('thead', null, h('tr', null, ['project', 'here', 'status'].map(k => h('th', null, t('reg.col.' + k))))),
        h('tbody', null, rows.map(r => h('tr', { class: r.m.error ? 'problem' : null },
          h('td', null, h('a', { href: routeHash({ view: 'regproject', rest: [r.m.project], ns: '' }) }, r.m.project)),
          h('td', null, r.m.error ? '—' : t(r.m.created ? 'reg.madeHere' : 'reg.hereAlready')),
          r.status)))),
      h('div', { class: 'dialog-actions' },
        h('a', { class: 'btn', href: routeHash({ view: 'regreplication', rest: [], ns: '' }), onclick: () => close() }, t('reg.toReplication')),
        h('button', { type: 'button', class: 'btn primary', onclick: () => close() }, t('done'))));
    const poll = async () => {
      if (!box.isConnected) return;
      let running = 0;
      for (const r of rows) {
        if (!r.m.job) continue;
        try {
          const j = await api('registry/jobs/' + enc(r.m.job));
          if (j.status === 'running') {
            running++;
            r.status.replaceChildren(progressText(ui, j.progress));
          } else {
            r.status.replaceChildren(j.error ? h('span', { class: 'status-bad' }, j.error) : jobSummary(ui, j));
          }
        } catch (e) {
          r.status.replaceChildren(h('span', { class: 'status-bad' }, e.message));
        }
      }
      if (running) setTimeout(poll, 1500);
      else ui.refresh();
    };
    poll();
  };
  const start = async () => {
    const projects = picks.filter(x => x.input.checked).map(x => x.p.name);
    if (!projects.length) {
      note.say(t('reg.pickProjects'), 'bad');
      return;
    }
    note.say(t('reg.waitJob'));
    try {
      runs(await api('registry/sources/' + enc(src.id) + '/migrate', { method: 'POST', body: { projects, sync: sync.checked } }));
    } catch (e) {
      note.say(e.message, 'bad');
    }
  };
  body.replaceChildren(...[
    h('p', { class: 'muted small-text' }, t('reg.migrateHint')),
    theirs.length ? h('table', { class: 'flat' },
      h('thead', null, h('tr', null, h('th'), ['project', 'repositories', 'access', 'here'].map(k => h('th', null, t('reg.col.' + k))))),
      h('tbody', null, picks.map(x => h('tr', null,
        h('td', null, x.input),
        h('td', null, h('strong', null, x.p.name)),
        h('td', null, x.p.repositories),
        h('td', null, src.kind === 'harbor' ? t(x.p.public ? 'reg.public' : 'reg.private') : h('span', { class: 'muted' }, '—')),
        h('td', null, here.has(x.p.name) ? t('reg.hereAlready') : h('span', { class: 'muted' }, '—'))))))
      : h('p', null, t('reg.noProjectsThere')),
    h('label', { class: 'check-item' }, sync, ' ', t('reg.migrateSync')),
    note,
    h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()),
      theirs.length ? h('button', { type: 'button', class: 'btn primary', onclick: start }, t('reg.migrateStart')) : null),
  ].filter(Boolean));
}

// ---------------------------------------------------------------- robot accounts

function robotsPage(data, ui) {
  const { h, t, button, age, emptyState, ask, api } = ui;
  const words = ui.words();
  const all = data.robots || [];
  const rows = all.filter(r => ui.matches(words, [r.login, r.description].concat(r.grants)));
  const head = ui.panel(null, h('div', { class: 'issue' },
    h('div', { class: 'what' }, h('div', { class: 'detail' }, t('reg.robotsHint'))),
    h('div', { class: 'actions' }, button('+ ' + t('reg.newRobot'), () => robotDialog(ui, data)))));
  if (!rows.length) return [problem(ui, data.info), head, emptyState(t(all.length ? 'noMatch' : 'reg.noRobots'))];
  return [problem(ui, data.info), head,
    h('table', null,
      h('thead', null, h('tr', null, ['robot', 'grants', 'expires', 'created'].map(k => h('th', null, t('reg.col.' + k))), h('th'))),
      h('tbody', null, rows.map(r => h('tr', { class: r.disabled || r.expired ? 'muted-row' : null },
        h('td', null, h('strong', { class: 'mono' }, r.login), r.description ? h('div', { class: 'muted small-text' }, r.description) : null,
          r.disabled ? ui.pill(t('reg.disabled'), 'bad') : null),
        h('td', null, ui.grantChips(r.grants)),
        h('td', null, r.expires ? (r.expired ? ui.pill(t('reg.expired'), 'bad') : ui.until(r.expires)) : h('span', { class: 'muted' }, t('reg.never'))),
        h('td', null, age(r.created), h('div', { class: 'muted small-text' }, r.by)),
        h('td', { class: 'actions-cell' }, h('div', { class: 'actions' },
          button(t('edit'), () => robotDialog(ui, data, r)),
          button(t('reg.rotate'), async () => {
            if (!(await ask({ title: t('reg.rotate'), message: t('reg.rotateConfirm', r.login), confirm: t('reg.rotate'), danger: true }))) return;
            try {
              const out = await api('registry/robots/' + enc(r.name) + '/rotate', { method: 'POST' });
              secretDialog(ui, data, out.robot, out.secret);
              ui.refresh();
            } catch (e) {
              ui.toast(e.message, true);
            }
          }),
          button(t('reg.deleteRobot'), async () => {
            if (!(await ask({ title: t('reg.deleteRobot'), message: t('reg.deleteRobotConfirm', r.login), confirm: t('reg.deleteRobot'), danger: true }))) return;
            act(ui, () => api('registry/robots/' + enc(r.name), { method: 'DELETE' }), t('reg.robotDeleted', r.login));
          }, 'danger'))))))),
    h('div', { class: 'more-note' }, t('reg.robotsNote'))];
}

function robotDialog(ui, data, robot) {
  const { h, t, button, modal, dialogField, formNote, api } = ui;
  const editing = !!robot;
  const name = h('input', { type: 'text', required: !editing, disabled: editing, value: editing ? robot.name : '', placeholder: 'ci' });
  const desc = h('input', { type: 'text', value: editing ? robot.description || '' : '' });
  const grants = h('textarea', { rows: '4', class: 'mono', placeholder: 'operator@registry:team-a\nviewer@registry:shared-*' });
  grants.value = editing ? robot.grants.join('\n') : '';
  const expires = h('input', { type: 'date', value: editing && robot.expires ? robot.expires.slice(0, 10) : '' });
  const expiresBefore = expires.value;
  const disabled = h('input', { type: 'checkbox', checked: editing && robot.disabled });
  const note = formNote();
  const form = h('form', {
    class: 'dialog',
    onsubmit: async e => {
      e.preventDefault();
      const body = {
        description: desc.value,
        grants: grants.value.split(/[\n,]+/).map(x => x.trim()).filter(Boolean),
      };
      // The day is all the field shows: an expiry left as it was keeps its
      // time too.
      if (!editing || expires.value !== expiresBefore) {
        body.expires = expires.value ? new Date(expires.value + 'T23:59:59Z').toISOString().replace(/\.\d+Z$/, 'Z') : '';
      }
      try {
        if (editing) {
          body.disabled = disabled.checked;
          await api('registry/robots/' + enc(robot.name), { method: 'PUT', body });
          close();
          ui.toast(t('reg.robotSaved', robot.login));
          ui.refresh();
        } else {
          body.name = name.value.trim();
          const out = await api('registry/robots', { method: 'POST', body });
          close();
          secretDialog(ui, data, out.robot, out.secret);
          ui.refresh();
        }
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, editing ? robot.login : t('reg.newRobot')),
  dialogField(t('reg.robotName'), name, t('reg.robotNameHelp')),
  dialogField(t('reg.description'), desc),
  dialogField(t('reg.col.grants'), grants, t('reg.robotGrantsHelp')),
  dialogField(t('reg.col.expires'), expires, t('reg.expiresHelp')),
  editing ? h('label', { class: 'check-item' }, disabled, ' ', t('reg.disabled')) : null,
  note,
  h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()), h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  (editing ? desc : name).focus();
}

// secretDialog shows a robot's secret, this once, with how to use it.
function secretDialog(ui, data, robot, secret) {
  const { h, t, modal } = ui;
  const reg = host(data.info);
  const form = h('div', { class: 'dialog wide' },
    h('h2', null, t('reg.secretTitle', robot.login)),
    h('p', { class: 'status-warn' }, t('reg.secretOnce')),
    command(ui, secret),
    h('p', { class: 'muted' }, t('reg.secretDocker')),
    command(ui, "echo '" + secret + "' | docker login " + reg + " -u '" + robot.login + "' --password-stdin"),
    h('p', { class: 'muted' }, t('reg.secretKube')),
    command(ui, 'kubectl create secret docker-registry kartal-pull --docker-server=' + reg + " --docker-username='" + robot.login +
      "' --docker-password='" + secret + "'"),
    h('div', { class: 'dialog-actions' }, h('button', { type: 'button', class: 'btn primary', onclick: () => close() }, t('reg.secretSaved'))));
  const close = modal(form);
}

// ---------------------------------------------------------------- vulnerabilities

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

// sevRank orders severities: 4 for critical down to 0 for unknown.
function sevRank(sev) {
  const i = SEVERITIES.indexOf(String(sev || '').toLowerCase());
  return i < 0 ? 0 : 4 - i;
}

// sevBar shows what is known of an artifact's vulnerabilities: how many of
// each severity (the worst of an index's images), and whether a scan
// waits, runs or failed, or none ever ran.
export function sevBar(ui, scan) {
  const { h, t } = ui;
  if (!scan) return null;
  const s = scan.summary;
  const parts = [];
  if (scan.status === 'queued' || scan.status === 'scanning') parts.push(ui.pill(t('reg.scan.' + scan.status), 'warn'));
  if (scan.status === 'failed') parts.push(h('span', { title: scan.error || '' }, ui.pill(t('reg.scan.failed'), 'bad')));
  if (s) {
    const counts = SEVERITIES.filter(k => s[k] > 0).map(k => h('span', { class: 'reg-sev reg-sev-' + k, title: t('reg.sev.' + k) }, t('reg.sevShort.' + k) + ' ' + s[k]));
    parts.push(counts.length ? counts : ui.pill(t('reg.scan.clean'), 'ok'));
  } else if (scan.status === 'none') {
    parts.push(h('span', { class: 'muted small-text' }, t('reg.scan.none')));
  }
  if (scan.images && scan.done < scan.images) parts.push(h('span', { class: 'muted small-text' }, t('reg.scan.ofImages', scan.done, scan.images)));
  if (scan.blocked) parts.push(h('span', { title: t('reg.blockedHelp', scan.blocked) }, ui.pill('⛔ ' + t('reg.blocked'), 'bad')));
  return h('span', { class: 'reg-sevbar' }, parts);
}

function scanButton(ui, repo, a) {
  return ui.button(ui.t('reg.scanNow'), () => act(ui, () => ui.api('registry/scan', { method: 'POST', body: { repo, digest: a.digest } }), ui.t('reg.scanQueued')));
}

// vulnPanel lists an image's vulnerabilities, as its last scan found them,
// to be narrowed by severity, by whether a fix is out, and by words.
function vulnPanel(ui, data) {
  const { h, t, mono, button } = ui;
  const v = data.vulns;
  const sc = v.scan || {};
  const rep = v.report;
  const sbom = v.sbom ? button(t('reg.sbomDownload'), async () => {
    try {
      const text = await ui.api('registry/sbom?repo=' + enc(data.repo) + '&digest=' + enc(data.artifact.digest), { text: true });
      ui.download(text, data.repo.split('/').pop() + '-' + shortDigest(data.artifact.digest) + '.cdx.json');
    } catch (e) {
      ui.toast(e.message, true);
    }
  }) : null;
  if (!rep) {
    const why = sc.status === 'failed' ? t('reg.lastScanFailed', sc.error || '') : sc.status === 'queued' || sc.status === 'scanning' ? t('reg.scanWaiting') : t('reg.notScannedYet');
    return ui.panel(t('reg.vulns'), h('p', { class: sc.status === 'failed' ? 'status-bad' : 'muted' }, why));
  }
  const vulns = rep.vulnerabilities || [];
  const project = data.project || {};
  const allowed = new Set((project.allowlist || []).map(x => x.toUpperCase()));
  const mayAllow = role(data) >= RANK.admin && !!(data.info && data.info.scanner);
  // allow puts a vulnerability on the project's allowlist, or takes it off.
  const allow = (id, on) => act(ui, async () => {
    const list = (project.allowlist || []).filter(x => x.toUpperCase() !== id.toUpperCase());
    if (on) list.push(id);
    await ui.api('registry/projects/' + enc(project.name), { method: 'PUT', body: { allowlist: list } });
  }, t(on ? 'reg.allowedNow' : 'reg.disallowedNow', id));
  const sev = h('select', { 'aria-label': t('reg.col.severity') }, h('option', { value: '' }, t('reg.sevAll')),
    SEVERITIES.slice(0, 4).map(k => h('option', { value: k }, t('reg.sevAtLeast', t('reg.sev.' + k)))));
  const fixable = h('input', { type: 'checkbox' });
  const q = h('input', { type: 'text', placeholder: t('reg.vulnSearch') });
  const tbody = h('tbody');
  const count = h('span', { class: 'muted small-text' });
  const shown = 500;
  const draw = () => {
    const min = sev.value ? sevRank(sev.value) : -1;
    const words = q.value.toLowerCase().split(/\s+/).filter(Boolean);
    const rows = vulns.filter(x => sevRank(x.severity) >= min && (!fixable.checked || x.fixed) &&
      words.every(w => [x.id, x.package, x.installed, x.fixed, x.title, x.target].some(f => String(f || '').toLowerCase().includes(w))));
    count.textContent = t('reg.vulnCount', rows.length, vulns.length);
    tbody.replaceChildren(...rows.slice(0, shown).map(x => {
      const s = String(x.severity || 'unknown').toLowerCase();
      return h('tr', null,
        h('td', null, h('span', { class: 'reg-sev reg-sev-' + s }, t('reg.sev.' + s)), x.score ? h('div', { class: 'muted small-text' }, x.score.toFixed(1)) : null),
        h('td', null, x.url && /^https:\/\//.test(x.url) ? h('a', { href: x.url, target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, x.id) : mono(x.id),
          allowed.has(String(x.id).toUpperCase()) ? h('div', null, ui.pill(t('reg.allowedChip'), 'ok')) : null),
        h('td', null, h('strong', null, x.package), x.target ? h('div', { class: 'muted small-text' }, x.target) : null),
        h('td', null, mono(x.installed || '')),
        h('td', null, x.fixed ? mono(x.fixed) : h('span', { class: 'muted' }, t('reg.noFix'))),
        h('td', { class: 'reg-step' }, x.title || ''),
        mayAllow ? h('td', { class: 'actions-cell' }, allowed.has(String(x.id).toUpperCase())
          ? ui.button(t('reg.disallow'), () => allow(x.id, false)) : ui.button(t('reg.allow'), () => allow(x.id, true))) : null);
    }), ...(rows.length > shown ? [h('tr', null, h('td', { colspan: mayAllow ? 7 : 6, class: 'muted' }, t('reg.vulnMore', rows.length - shown)))] : []));
  };
  [sev, fixable].forEach(el => el.addEventListener('change', draw));
  q.addEventListener('input', draw);
  draw();
  const about = [rep.os, t('reg.packages', rep.packages || 0), rep.scanner, rep.db ? t('reg.dbOf', ui.ago(rep.db)) : null,
    sc.scanned ? t('reg.scannedAgo', ui.ago(sc.scanned)) : null].filter(Boolean).join(' · ');
  return ui.panel(t('reg.vulns'), h('div', { class: 'reg-body' },
    h('div', { class: 'reg-filters' }, h('span', { class: 'muted small-text' }, about), sbom),
    sc.status === 'failed' ? h('div', { class: 'status-bad small-text' }, t('reg.lastScanFailed', sc.error || '')) : null,
    sc.status === 'queued' || sc.status === 'scanning' ? h('div', { class: 'status-warn small-text' }, t('reg.scanWaiting')) : null,
    data.artifact.scan && data.artifact.scan.blocked ? h('div', { class: 'status-bad' }, '⛔ ', t('reg.blockedHelp', data.artifact.scan.blocked)) : null,
    vulns.length ? [h('div', { class: 'reg-filters' }, sev, h('label', { class: 'check-item' }, fixable, ' ', t('reg.fixableOnly')), q, count),
      h('table', { class: 'flat' }, h('thead', null, h('tr', null, ['severity', 'vuln', 'package', 'installed', 'fixed', 'title'].map(k => h('th', null, t('reg.col.' + k))),
        mayAllow ? h('th') : null)), tbody)]
      : h('p', { class: 'status-ok' }, t('reg.noVulns'))));
}

// scannerPanel tells the registry's admins of its scanner: Trivy's version,
// how old its databases are, and what waits to be scanned.
function scannerPanel(ui, data) {
  const { h, t, button, api } = ui;
  const v = data.scanner;
  if (!v || !v.configured) return null;
  const st = v.status || null;
  const kv = (k, val) => val == null || val === '' ? null : h('div', { class: 'kv-row' }, h('span', { class: 'kv-key' }, t(k)), h('span', { class: 'kv-value' }, val));
  const dbText = db => db && db.updatedAt ? t('reg.dbBuilt', ui.ago(db.updatedAt)) + (db.downloadedAt ? ' · ' + t('reg.dbFetched', ui.ago(db.downloadedAt)) : '') : t('reg.noDB');
  return ui.panel(t('reg.scanner'), h('div', { class: 'reg-body' },
    v.problem ? h('div', { class: 'status-bad' }, t('reg.scannerProblem', v.problem)) : null,
    st && st.updating ? h('div', { class: 'status-warn' }, t('reg.dbUpdating')) : null,
    st && st.updateError ? h('div', { class: 'status-bad small-text' }, t('reg.dbUpdateFailed', st.updateError)) : null,
    h('div', { class: 'kv' },
      kv('reg.scannerVersion', st ? st.scanner : null),
      kv('reg.scannerDB', st ? dbText(st.db) : null),
      kv('reg.scannerJavaDB', st ? dbText(st.javaDB) : null),
      kv('reg.scannerDBFrom', st ? [st.dbRepository, st.javaDBRepository].filter(Boolean).join(', ') || t('reg.dbFromTrivy') : null),
      kv('reg.scannerQueue', t('reg.scannerQueueText', v.queued || 0, st ? st.scanning : 0, st ? st.workers : 0)),
      kv('reg.scannerPulls', v.address ? ui.mono(v.address) : null)),
    h('div', { class: 'actions' }, button(t('reg.updateDB'), () => act(ui, () => api('registry/scanner/db', { method: 'POST' }), t('reg.dbUpdateStarted'))))), 'reg-events');
}

// ---------------------------------------------------------------- what runs

// runningPage lists the registry's images that the clusters run, where the
// user may look, the worst first: what Kartal Gözü knows that a registry
// alone does not.
function runningPage(data, ui) {
  const { h, t, emptyState, routeHash } = ui;
  const all = (data.running && data.running.images) || [];
  const onlyBad = h('input', { type: 'checkbox', checked: true });
  const words = ui.words();
  const bad = r => r.scan && r.scan.summary && (r.scan.summary.critical || r.scan.summary.high || r.critical);
  const tbody = h('tbody');
  const count = h('span', { class: 'muted small-text' });
  const draw = () => {
    const rows = all.filter(r => (!onlyBad.checked || bad(r)) && ui.matches(words, [r.cluster, r.namespace, r.workload, r.repo, r.digest]));
    count.textContent = t('reg.vulnCount', rows.length, all.length);
    tbody.replaceChildren(...rows.map(r => h('tr', { class: r.critical ? 'problem' : null },
      h('td', null, r.cluster), h('td', null, r.namespace), h('td', null, h('strong', null, r.workload)), h('td', null, r.pods),
      h('td', null, h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [r.repo, r.digest], ns: '' }), title: r.digest },
        r.repo + '@' + shortDigest(r.digest))),
      h('td', null, sevBar(ui, r.scan) || h('span', { class: 'muted' }, '—')),
      h('td', null, r.critical ? h('span', { class: 'status-bad' }, r.critical) : h('span', { class: 'muted' }, '0')))));
  };
  onlyBad.addEventListener('change', draw);
  draw();
  const head = ui.panel(null, h('div', { class: 'issue' }, h('div', { class: 'what' },
    h('div', { class: 'detail' }, t('reg.runningHint')),
    data.info && !data.info.scanner ? h('div', { class: 'detail status-warn' }, t('reg.noScannerRunning')) : null)));
  if (!all.length) return [problem(ui, data.info), head, emptyState(t('reg.noRunning'))];
  return [problem(ui, data.info), head,
    h('div', { class: 'reg-filters' }, h('label', { class: 'check-item' }, onlyBad, ' ', t('reg.onlyVulnerable')), count),
    h('table', null, h('thead', null, h('tr', null, ['cluster', 'namespace', 'workload', 'pods', 'image', 'vulns', 'unallowed'].map(k =>
      h('th', { title: k === 'unallowed' ? t('reg.unallowedHelp') : null }, t('reg.col.' + k))))), tbody),
    h('div', { class: 'more-note' }, t('reg.runningNote'))];
}

// trivyDialog makes the rules that copy Trivy's databases into a project,
// for a scanner that cannot reach the internet: each night, the tags
// Trivy reads.
function trivyDialog(ui, data) {
  const { h, t, button, modal, dialogField, formNote, api } = ui;
  const source = h('select', null, (data.sources || []).map(x => h('option', { value: x.id }, x.name + ' (' + t('reg.kindSrc.' + x.kind) + ')')));
  const projects = data.projects || [];
  const project = h('select', null, projects.map(p => h('option', { value: p.name, selected: p.name === 'trivy' }, p.name)));
  const note = formNote();
  const form = h('form', {
    class: 'dialog wide',
    onsubmit: async e => {
      e.preventDefault();
      try {
        for (const [repo, tag, name] of [['aquasecurity/trivy-db', '2', 'Trivy vulnerability DB'], ['aquasecurity/trivy-java-db', '1', 'Trivy Java DB']]) {
          await api('registry/rules', { method: 'POST', body: { name, source: source.value, repositories: repo, tags: tag, project: project.value,
            overwrite: true, concurrency: 1, cron: '0 4 * * *', enabled: true } });
        }
        close();
        ui.toast(t('reg.trivyMade', project.value));
        ui.refresh();
      } catch (err) {
        note.say(err.message, 'bad');
      }
    },
  }, h('h2', null, t('reg.trivyTemplate')),
  h('p', { class: 'muted' }, t('reg.trivyTemplateHelp')),
  dialogField(t('reg.ruleSource'), source, t('reg.trivySourceHelp')),
  dialogField(t('reg.ruleProject'), project, t('reg.trivyProjectHelp')),
  note,
  h('div', { class: 'dialog-actions' }, button(t('cancel'), () => close()), h('button', { type: 'submit', class: 'btn primary', disabled: !projects.length }, t('save'))));
  const close = modal(form);
}
