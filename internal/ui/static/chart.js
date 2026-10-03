// Small line charts drawn as SVG, with a hover readout. No dependencies.
// Colours come from CSS classes, so the charts follow the theme.

const NS = 'http://www.w3.org/2000/svg';
const W = 600;

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

function clock(t) {
  return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// lineChart draws one series over time.
//   points: [{t, ...}] oldest first; value(p) picks the number to draw
//   format(n) writes a value for people; guides: [{label, value}] dashed
//   lines such as a request or a limit; empty: text when there is nothing.
export function lineChart({ title, points, value, format, guides = [], height = 120, empty = '—' }) {
  const box = div('chart');
  const head = div('chart-head');
  const now = points.length ? format(value(points[points.length - 1])) : '—';
  head.append(div('chart-title', title), div('chart-value', now));
  box.append(head);
  if (points.length < 2) {
    box.append(div('chart-empty', empty));
    return box;
  }
  const values = points.map(value);
  // Small values, such as a few errors a second, still fill the chart.
  const highest = Math.max(...values);
  const peak = highest > 0 ? highest : 1;
  // A guide far above the data, such as a node's whole capacity, would
  // flatten the line into the floor; those are only named below the chart.
  const drawn = guides.filter(g => g.value > 0 && g.value <= peak * 4);
  const scaleMax = Math.max(peak, ...drawn.map(g => g.value));
  const top = scaleMax * 1.1;
  const t0 = points[0].t;
  const t1 = points[points.length - 1].t;
  const x = t => ((t - t0) / Math.max(1, t1 - t0)) * W;
  const y = v => height - (v / top) * height;

  const plot = svg('svg', { viewBox: `0 0 ${W} ${height}`, preserveAspectRatio: 'none', class: 'chart-svg' });
  for (const f of [0.25, 0.5, 0.75]) {
    plot.append(svg('line', { x1: 0, x2: W, y1: height * f, y2: height * f, class: 'chart-grid', 'vector-effect': 'non-scaling-stroke' }));
  }
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(values[i]).toFixed(1)}`).join('');
  plot.append(svg('path', { d: `${line}L${W},${height}L0,${height}Z`, class: 'chart-area' }));
  plot.append(svg('path', { d: line, class: 'chart-line', 'vector-effect': 'non-scaling-stroke' }));
  const labels = div('chart-guides');
  for (const g of guides) {
    if (!(g.value > 0)) continue;
    const shown = drawn.includes(g);
    if (shown) plot.append(svg('line', { x1: 0, x2: W, y1: y(g.value), y2: y(g.value), class: 'chart-guide', 'vector-effect': 'non-scaling-stroke' }));
    labels.append(div(shown ? 'chart-guide-label' : 'chart-guide-label off', `${g.label}: ${format(g.value)}`));
  }

  const body = div('chart-body');
  const cursor = div('chart-cursor');
  const tip = div('chart-tip');
  cursor.hidden = tip.hidden = true;
  body.append(plot, div('chart-max', format(scaleMax)), cursor, tip);
  body.addEventListener('mousemove', e => {
    const r = body.getBoundingClientRect();
    const frac = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
    const target = t0 + frac * (t1 - t0);
    let best = 0;
    for (let i = 1; i < points.length; i++) {
      if (Math.abs(points[i].t - target) < Math.abs(points[best].t - target)) best = i;
    }
    const left = (x(points[best].t) / W) * 100;
    cursor.hidden = tip.hidden = false;
    cursor.style.left = left + '%';
    tip.style.left = Math.min(left, 70) + '%';
    tip.textContent = clock(points[best].t) + ' · ' + format(values[best]);
  });
  body.addEventListener('mouseleave', () => { cursor.hidden = tip.hidden = true; });

  const axis = div('chart-axis');
  axis.append(div('', clock(t0)), div('', clock(t1)));
  box.append(body, axis);
  if (labels.childNodes.length) box.append(labels);
  return box;
}
