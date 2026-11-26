// The image registry's pages: its projects, a project, a repository's
// artifacts, an artifact, and the robot accounts. app.js hands in its
// helpers (ui) and the data it loaded with loadRegistry; nothing here keeps
// state of its own.

export const REGISTRY_VIEWS = ['registry', 'regproject', 'regrepo', 'regartifact', 'regjobs', 'robots'];

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
      return { info, project, repo, artifact };
    }
    case 'regjobs':
      return { info, jobs: await api('registry/jobs?limit=100', { signal }) };
    case 'robots':
      return { info, robots: await api('registry/robots', { signal }) };
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
    case 'robots': return robotsPage(data, ui);
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
  const note = formNote();
  const form = h('form', {
    class: 'dialog',
    onsubmit: async e => {
      e.preventDefault();
      const body = { public: pub.checked, description: desc.value, immutable: rules.value.split(/[\s,]+/).filter(Boolean) };
      if (admin) body.quota = quota.value ? Math.round(Number(quota.value) * GIB) : 0;
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
          p.immutable.map(x => h('span', { class: 'label-chip reg-tag' }, '🔒 ', x))) : null),
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
      h('thead', null, h('tr', null, ['artifact', 'tags', 'kind', 'platform', 'size', 'pushed', 'lastPull', 'pulls'].map(k => h('th', null, t('reg.col.' + k))), h('th'))),
      h('tbody', null, arts.map(a => h('tr', null,
        h('td', null, h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [repo, a.digest], ns: '' }), title: a.digest }, shortDigest(a.digest)),
          a.referrers ? h('span', { class: 'muted small-text', title: t('reg.referrersHelp') }, ' · ' + t('reg.referrerCount', a.referrers)) : null),
        h('td', null, a.tags.length ? a.tags.map(tag => tagChip(a, tag)) : h('span', { class: 'muted' }, t('reg.untagged'))),
        h('td', null, kindPill(ui, a.kind)),
        h('td', null, platformText(a) || '—'),
        h('td', null, bytes(a.total)),
        h('td', null, age(a.pushed), a.pushedBy ? h('div', { class: 'muted small-text' }, a.pushedBy) : null),
        h('td', null, a.lastPull ? age(a.lastPull) : h('span', { class: 'muted' }, t('reg.never'))),
        h('td', null, a.pulls),
        h('td', { class: 'actions-cell' }, h('div', { class: 'actions' },
          button(t('reg.copyPull'), () => copyText('docker pull ' + reg + '/' + repo + (a.tags.length ? ':' + a.tags[0] : '@' + a.digest))),
          mine >= RANK.operator ? button('+ ' + t('reg.tag'), () => addTag(a)) : null,
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
      kv('reg.subject', a.subject ? h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [repo, a.subject], ns: '' }) }, shortDigest(a.subject)) : null)),
    h('div', { class: 'reg-commands' }, command(ui, 'docker pull ' + reg + '/' + repo + '@' + a.digest))));
  const parts = [problem(ui, data.info), summary];
  if (a.children && a.children.length) {
    parts.push(ui.panel(t('reg.children'), h('table', { class: 'flat' },
      h('thead', null, h('tr', null, ['platform', 'artifact', 'size'].map(k => h('th', null, t('reg.col.' + k))))),
      h('tbody', null, a.children.map(c => h('tr', null, h('td', null, platformText(c) || '—'),
        h('td', null, h('a', { class: 'mono', href: routeHash({ view: 'regartifact', rest: [repo, c.digest], ns: '' }) }, shortDigest(c.digest))),
        h('td', null, bytes(c.total))))))));
  }
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
    if (j.status === 'running' && ++tries < 120) {
      setTimeout(poll, 1000);
      return;
    }
    const r = j.report || {};
    const removed = r.removed || [];
    body.replaceChildren(
      j.error ? h('p', { class: 'status-bad' }, j.error) : h('p', null, jobSummary(ui, j)),
      r.unknown && r.unknown.length ? h('p', { class: 'muted small-text' }, t('reg.retentionUnknown', r.unknown.join(', '))) : null,
      removed.length ? h('table', { class: 'flat' },
        h('thead', null, h('tr', null, ['repository', 'artifact', 'tags', 'pushed'].map(k => h('th', null, t('reg.col.' + k))))),
        h('tbody', null, removed.map(x => h('tr', null, h('td', null, x.repo), h('td', null, ui.mono(shortDigest(x.digest))),
          h('td', null, x.tags && x.tags.length ? x.tags.join(', ') : h('span', { class: 'muted' }, t('reg.untagged'))), h('td', null, ui.age(x.pushed))))))
        : j.status === 'done' ? h('p', { class: 'muted' }, t('reg.removedNone')) : null);
    ui.refresh();
  };
  poll();
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
      button(t('reg.retentionAllDry'), () => start('retention', true)))));
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
      h('td', null, t('reg.job.' + j.kind), j.project ? h('span', { class: 'muted' }, ' · ' + j.project) : null,
        j.dryRun ? h('span', { class: 'muted' }, ' · ' + t('reg.dryRun')) : null),
      h('td', null, j.by === 'schedule' ? h('span', { class: 'muted' }, t('reg.bySchedule')) : j.by),
      h('td', null, age(j.started)),
      h('td', null, j.finished ? ui.duration(j.started, j.finished) : '…'),
      h('td', null, jobState(ui, j)),
      h('td', null, j.error ? h('span', { class: 'status-bad' }, j.error) : [jobSummary(ui, j),
        j.alarm ? h('div', { class: 'status-bad small-text' }, t('reg.verifyAlarm', ((j.report || {}).corrupt || []).length,
          ((j.report || {}).missing || []).length)) : null]))))) : emptyState(t('reg.noJobs'));
  return [problem(ui, data.info), head, sched, h('div', { class: 'reg-events' }, history)];
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
