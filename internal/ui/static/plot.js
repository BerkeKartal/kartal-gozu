// Charts of many series over time, drawn as SVG: axes, lines, areas or
// stacks, a readout of every series under the pointer, and zooming by
// dragging across. No dependencies; colours of the frame come from CSS.

const NS = 'http://www.w3.org/2000/svg';
const W = 1000;

function svg(tag, attrs) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function div(cls, text) {
  const el = document.createElement('div');
  el.className = cls;
  if (text != null) el.textContent = text;
  return el;
}

// num is a value that can be drawn: a finite number, or null.
function num(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
function orderValue(v) {
  const n = num(v);
  return n == null ? -Infinity : n;
}

// niceStep is a round step that splits span into about n parts.
export function niceStep(span, n) {
  const raw = span / Math.max(1, n);
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (raw <= m * mag) return m * mag;
  }
  return 10 * mag;
}

// Steps for the time axis, in milliseconds.
const TIME_STEPS = [1, 5, 10, 15, 30].map(s => s * 1000)
  .concat([1, 2, 5, 10, 15, 30].map(m => m * 60000))
  .concat([1, 2, 3, 6, 12].map(h => h * 3600000))
  .concat([1, 2, 7, 14, 30].map(d => d * 86400000));

function timeTicks(t0, t1, n) {
  const want = (t1 - t0) / Math.max(1, n);
  const step = TIME_STEPS.find(s => s >= want) || TIME_STEPS[TIME_STEPS.length - 1];
  // Ticks fall on round local times.
  const off = new Date(t0).getTimezoneOffset() * 60000;
  const first = Math.ceil((t0 - off) / step) * step + off;
  const out = [];
  for (let t = first; t <= t1; t += step) out.push(t);
  return out;
}

export function timeLabel(t, span) {
  const d = new Date(t);
  const hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: span < 300000 ? '2-digit' : undefined });
  if (span <= 86400000) return hm;
  return d.toLocaleDateString([], { day: '2-digit', month: '2-digit' }) + ' ' + hm;
}

// plot draws the series.
//   series: [{ name, color, values }] with a value (or null) at each step
//   start, step: the first step's time and the time between steps (ms)
//   format(v): a value for people; mode: 'lines', 'area' or 'stacked'
//   onZoom(from, to): called with the range dragged across
//   empty: the text shown when there is nothing to draw
export function plot({ series, start, step, count, height = 300, format = String, mode = 'lines', onZoom, empty = '—', min: yMinSet, max: yMaxSet }) {
  const box = div('plot');
  const end = start + step * Math.max(0, count - 1);
  const span = Math.max(1, end - start);
  const stacked = mode === 'stacked';
  // Stacks add up the values drawn so far at each step.
  const drawn = series.map(s => ({ s, v: s.values.map(num) }));
  if (stacked) {
    const acc = new Array(count).fill(0);
    for (const d of drawn) {
      d.base = acc.slice();
      d.v = d.v.map((x, i) => (x == null ? null : (acc[i] += x)));
    }
  }
  let lo = Infinity;
  let hi = -Infinity;
  for (const d of drawn) {
    for (const x of d.v) {
      if (x == null) continue;
      if (x < lo) lo = x;
      if (x > hi) hi = x;
    }
  }
  if (!Number.isFinite(lo)) {
    box.append(div('plot-empty', empty));
    return box;
  }
  if (mode !== 'lines' || lo > 0) lo = Math.min(lo, 0);
  if (yMinSet != null) lo = yMinSet;
  if (yMaxSet != null) hi = yMaxSet;
  if (hi === lo) {
    hi += Math.abs(hi) || 1;
    if (mode === 'lines' && lo !== 0) lo -= Math.abs(lo);
  }
  const ystep = niceStep(hi - lo, 5);
  const top = yMaxSet != null ? hi : Math.ceil(hi / ystep - 1e-9) * ystep;
  const bottom = yMinSet != null ? lo : Math.floor(lo / ystep + 1e-9) * ystep;
  const x = i => (count > 1 ? (i / (count - 1)) * W : W / 2);
  const y = v => height - ((v - bottom) / Math.max(1e-300, top - bottom)) * height;

  const g = svg('svg', { viewBox: `0 0 ${W} ${height}`, preserveAspectRatio: 'none', class: 'plot-svg' });
  const yAxis = div('plot-y');
  for (let v = bottom; v <= top + ystep / 2; v += ystep) {
    const yy = y(v);
    g.append(svg('line', { x1: 0, x2: W, y1: yy, y2: yy, class: Math.abs(v) < ystep / 1e6 ? 'plot-zero' : 'plot-grid', 'vector-effect': 'non-scaling-stroke' }));
    const label = div('plot-ylabel', format(Math.abs(v) < ystep / 1e6 ? 0 : v));
    label.style.top = (yy / height) * 100 + '%';
    yAxis.append(label);
  }
  const xAxis = div('plot-x');
  for (const t of timeTicks(start, end, 8)) {
    const fx = ((t - start) / span) * 100;
    g.append(svg('line', { x1: fx * W / 100, x2: fx * W / 100, y1: 0, y2: height, class: 'plot-grid', 'vector-effect': 'non-scaling-stroke' }));
    const label = div('plot-xlabel', timeLabel(t, span));
    label.style.left = fx + '%';
    xAxis.append(label);
  }
  for (const d of drawn) {
    let path = '';
    let fill = '';
    let run = [];
    const flush = () => {
      if (!run.length) return;
      if (run.length === 1) {
        // A lone value between gaps shows as a short mark.
        const px = x(run[0]);
        const py = y(d.v[run[0]]).toFixed(1);
        path += `M${(px - 1.5).toFixed(1)},${py}L${(px + 1.5).toFixed(1)},${py}`;
        run = [];
        return;
      }
      path += run.map((i, k) => `${k ? 'L' : 'M'}${x(i).toFixed(1)},${y(d.v[i]).toFixed(1)}`).join('');
      if (mode !== 'lines') {
        const base = i => (stacked ? d.base[i] : Math.max(bottom, Math.min(top, 0)));
        const back = run.slice().reverse().map(i => `L${x(i).toFixed(1)},${y(base(i)).toFixed(1)}`).join('');
        fill += run.map((i, k) => `${k ? 'L' : 'M'}${x(i).toFixed(1)},${y(d.v[i]).toFixed(1)}`).join('') + back + 'Z';
      }
      run = [];
    };
    d.v.forEach((v, i) => (v == null ? flush() : run.push(i)));
    flush();
    if (fill) g.append(svg('path', { d: fill, fill: d.s.color, 'fill-opacity': stacked ? '0.45' : '0.12', stroke: 'none' }));
    g.append(svg('path', { d: path, fill: 'none', stroke: d.s.color, 'stroke-width': '1.5', 'stroke-linejoin': 'round', 'stroke-linecap': 'round', 'vector-effect': 'non-scaling-stroke' }));
  }

  const body = div('plot-body');
  body.style.height = height + 'px';
  const cursor = div('plot-cursor');
  const sel = div('plot-sel');
  const tip = div('plot-tip');
  cursor.hidden = sel.hidden = tip.hidden = true;
  body.append(g, cursor, sel, tip);

  const indexAt = clientX => {
    const r = body.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (clientX - r.left) / r.width));
    return { f, i: count > 1 ? Math.round(f * (count - 1)) : 0 };
  };
  let dragFrom = null;
  body.addEventListener('mousedown', e => {
    if (e.button !== 0 || !onZoom) return;
    dragFrom = indexAt(e.clientX).f;
    e.preventDefault();
  });
  const show = e => {
    const { f, i } = indexAt(e.clientX);
    const left = (x(i) / W) * 100;
    cursor.hidden = false;
    cursor.style.left = left + '%';
    if (dragFrom != null) {
      sel.hidden = false;
      sel.style.left = Math.min(dragFrom, f) * 100 + '%';
      sel.style.width = Math.abs(f - dragFrom) * 100 + '%';
      tip.hidden = true;
      return;
    }
    const rows = series.map(s => ({ s, v: s.values[i] }))
      .filter(r => r.v != null)
      .sort((a, b) => orderValue(b.v) - orderValue(a.v));
    tip.replaceChildren(div('plot-tip-time', new Date(start + i * step).toLocaleString()));
    for (const r of rows.slice(0, 12)) {
      const line = div('plot-tip-row');
      const dot = div('plot-dot');
      dot.style.background = r.s.color;
      line.append(dot, div('plot-tip-name', r.s.name), div('plot-tip-value', typeof r.v === 'number' ? format(r.v) : String(r.v)));
      tip.append(line);
    }
    if (rows.length > 12) tip.append(div('plot-tip-more', '+' + (rows.length - 12)));
    if (!rows.length) tip.append(div('plot-tip-more', '—'));
    tip.hidden = false;
    const right = left > 55;
    tip.style.left = right ? '' : 'calc(' + left + '% + 12px)';
    tip.style.right = right ? 'calc(' + (100 - left) + '% + 12px)' : '';
  };
  body.addEventListener('mousemove', show);
  body.addEventListener('mouseleave', () => {
    cursor.hidden = tip.hidden = true;
    if (dragFrom != null) {
      dragFrom = null;
      sel.hidden = true;
    }
  });
  body.addEventListener('mouseup', e => {
    if (dragFrom == null) return;
    const to = indexAt(e.clientX).f;
    const from = dragFrom;
    dragFrom = null;
    sel.hidden = true;
    const r = body.getBoundingClientRect();
    if (Math.abs(to - from) * r.width < 5) return;
    const a = start + Math.min(from, to) * span;
    const b = start + Math.max(from, to) * span;
    onZoom(Math.round(a), Math.round(b));
  });

  const frame = div('plot-frame');
  frame.append(yAxis, body);
  box.append(frame, xAxis);
  return box;
}

// sparkline draws values small, without axes: a stat panel's trend. Its
// colour is the text's unless one is given.
export function sparkline(values, color, height = 36) {
  const v = values.map(num);
  const box = div('spark');
  box.style.height = height + 'px';
  let lo = Infinity;
  let hi = -Infinity;
  for (const x of v) {
    if (x == null) continue;
    if (x < lo) lo = x;
    if (x > hi) hi = x;
  }
  if (!Number.isFinite(lo)) return box;
  if (hi === lo) {
    hi += 1;
    lo -= 1;
  }
  const n = v.length;
  const xs = i => (n > 1 ? (i / (n - 1)) * W : W / 2).toFixed(1);
  const ys = x => (height - 2 - ((x - lo) / (hi - lo)) * (height - 4)).toFixed(1);
  let line = '';
  let area = '';
  let run = [];
  const flush = () => {
    if (run.length > 1) {
      const path = run.map((i, k) => `${k ? 'L' : 'M'}${xs(i)},${ys(v[i])}`).join('');
      line += path;
      area += path + `L${xs(run[run.length - 1])},${height}L${xs(run[0])},${height}Z`;
    }
    run = [];
  };
  v.forEach((x, i) => (x == null ? flush() : run.push(i)));
  flush();
  const g = svg('svg', { viewBox: `0 0 ${W} ${height}`, preserveAspectRatio: 'none', class: 'plot-svg' });
  g.append(svg('path', { d: area, fill: color || 'currentColor', 'fill-opacity': '0.15', stroke: 'none' }),
    svg('path', { d: line, fill: 'none', stroke: color || 'currentColor', 'stroke-width': '1.5', 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke' }));
  box.append(g);
  return box;
}
