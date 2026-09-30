// YAML for JSON values, laid out the way "kubectl get -o yaml" does, and a
// line diff for previewing edits. No dependencies.

const SPECIAL_FIRST = new Set([...'-?:,[]{}#&*!|>\'"%@`']);
// Words YAML 1.1 (which the API server reads) does not take as text; "<<"
// is its merge key and "=" its value key.
const KEYWORD = /^(true|false|yes|no|on|off|y|n|null|~|<<|=)$/i;
const NUMBER = /^[-+]?(\.[0-9]+|[0-9][0-9_]*(\.[0-9]*)?)([eE][-+]?[0-9]+)?$|^[-+]?0x[0-9a-f_]+$|^[-+]?0o[0-7_]+$|^[-+]?0b[01_]+$|^[-+]?\.(inf|nan)$/i;
const DATE = /^\d{4}-\d\d?-\d\d?([Tt ]|$)/;

// plain reports whether a string can be written without quotes and still
// read back as the same string.
function plain(s) {
  return s !== '' && s.trim() === s && !SPECIAL_FIRST.has(s[0]) && !s.includes(': ') && !s.includes(' #') &&
    !s.endsWith(':') && !/[\n\r\t\u0000-\u001f\u007f﻿]/.test(s) && !KEYWORD.test(s) && !NUMBER.test(s) && !DATE.test(s);
}

function str(s) {
  return plain(s) ? s : JSON.stringify(s);
}

// A multi-line string becomes a literal block when that round-trips exactly.
function literal(s) {
  return s.includes('\n') && !/[\r\u0000-\u0008\u000b-\u001f\u007f]/.test(s) && !/^[ \t]/.test(s);
}

function isEmpty(v) {
  return Array.isArray(v) ? v.length === 0 : v !== null && typeof v === 'object' && Object.keys(v).length === 0;
}
function isLeaf(v) {
  return v === null || v === undefined || typeof v !== 'object' || isEmpty(v);
}

function scalar(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return str(v);
  if (Array.isArray(v)) return '[]';
  if (typeof v === 'object') return '{}';
  return String(v);
}

// leaf appends "prefix value", or a literal block for multi-line text.
function leaf(out, prefix, v, pad) {
  if (typeof v === 'string' && literal(v)) {
    const trailing = v.match(/\n*$/)[0].length;
    const chomp = trailing === 0 ? '-' : trailing === 1 ? '' : '+';
    out.push(prefix + '|' + chomp);
    // The last line break ends the last line; with "+" the empty lines
    // after it are kept as lines of their own.
    const body = trailing === 0 ? v : v.slice(0, -1);
    for (const line of body.split('\n')) out.push(line === '' ? '' : pad + '  ' + line);
    return;
  }
  out.push(prefix + scalar(v));
}

function block(out, v, pad) {
  if (Array.isArray(v)) {
    for (const item of v) {
      if (isLeaf(item)) {
        leaf(out, pad + '- ', item, pad);
        continue;
      }
      const start = out.length;
      block(out, item, pad + '  ');
      // The item's first line starts where its dash goes.
      out[start] = pad + '- ' + out[start].slice(pad.length + 2);
    }
    return;
  }
  for (const [key, val] of Object.entries(v)) {
    const k = pad + str(key) + ':';
    if (isLeaf(val)) {
      leaf(out, k + ' ', val, pad);
    } else {
      out.push(k);
      // Like kubectl, a list under a key is not indented further.
      block(out, val, Array.isArray(val) ? pad : pad + '  ');
    }
  }
}

export function toYAML(value) {
  if (isLeaf(value)) return scalar(value) + '\n';
  const out = [];
  block(out, value, '');
  return out.join('\n') + '\n';
}

// diffLines compares two texts line by line (Myers' algorithm) and returns
// [{t: ' ' | '-' | '+', s: line}], or null when they differ too much to be
// worth showing line by line.
export function diffLines(a, b, limit = 2000) {
  const A = a.split('\n');
  const B = b.split('\n');
  const n = A.length;
  const m = B.length;
  const max = n + m;
  const v = new Int32Array(2 * max + 3);
  const trace = [];
  let done = false;
  for (let d = 0; d <= max && !done; d++) {
    if (d > limit) return null;
    // Keep only the diagonals step d can read: -d-1 .. d+1.
    trace.push(v.slice(max - d - 1 + 1, max + d + 3));
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[max + k] < v[max + k + 2]) ? v[max + k + 2] : v[max + k] + 1;
      let y = x - k;
      while (x < n && y < m && A[x] === B[y]) {
        x++;
        y++;
      }
      v[max + k + 1] = x;
      if (x >= n && y >= m) {
        done = true;
        break;
      }
    }
  }
  const out = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0; d--) {
    const vv = trace[d];
    const at = k => vv[k + d + 1]; // v[k] as it was before step d
    const k = x - y;
    const prevK = k === -d || (k !== d && at(k - 1) < at(k + 1)) ? k + 1 : k - 1;
    const prevX = at(prevK);
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      out.push({ t: ' ', s: A[x - 1] });
      x--;
      y--;
    }
    if (d > 0) {
      if (x === prevX) out.push({ t: '+', s: B[prevY] });
      else out.push({ t: '-', s: A[prevX] });
    }
    x = prevX;
    y = prevY;
  }
  return out.reverse();
}
