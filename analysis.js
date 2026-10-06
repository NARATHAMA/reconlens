// Logika analisis murni (tanpa API Chrome) agar mudah diuji.
(function (root) {
  const SLD = new Set(['co', 'com', 'or', 'org', 'ac', 'go', 'gov', 'net', 'web', 'my', 'sch', 'edu', 'mil', 'ne']);

  function regDomain(host) {
    const p = host.split('.');
    if (p.length <= 2 || /^\d+(\.\d+){3}$/.test(host)) return host;
    const n = p.length;
    if (p[n - 1].length === 2 && SLD.has(p[n - 2])) return p.slice(-3).join('.');
    return p.slice(-2).join('.');
  }

  function hmap(arr) {
    const m = {};
    for (const { n, v } of arr || []) { const k = n.toLowerCase(); m[k] = m[k] ? m[k] + ', ' + v : v; }
    return m;
  }

  function detect(d, sigs, tpCats) {
    const out = [];
    const res = (d.resources || []).join('\n');
    for (const s of sigs) {
      let hit = false, ver = '';
      const take = (m) => { hit = true; if (!ver && m && m[1]) ver = m[1]; };
      if (s.h) for (const k in s.h) if (d.headers[k] !== undefined) { const m = new RegExp(s.h[k], 'i').exec(d.headers[k]); if (m) take(m); }
      if (s.meta) for (const k in s.meta) if (d.meta[k] !== undefined) { const m = new RegExp(s.meta[k], 'i').exec(d.meta[k]); if (m) take(m); }
      if (s.ck) for (const re of s.ck) { const r = new RegExp(re); if (d.cookies.some((c) => r.test(c))) hit = true; }
      if (s.s) for (const re of s.s) { const m = new RegExp(re, 'i').exec(res); if (m) take(m); }
      if (s.html) for (const re of s.html) { const m = new RegExp(re, 'i').exec(d.html || ''); if (m) take(m); }
      if (s.js) for (const p of s.js) if (d.globals[p] !== undefined) { hit = true; if (!ver && typeof d.globals[p] === 'string' && /^\d/.test(d.globals[p])) ver = d.globals[p]; }
      if (hit) out.push({ name: s.n, cat: s.c || 'Lainnya', version: ver });
    }
    return out;
  }

  function cspIssues(v) {
    const d = {};
    v.split(';').forEach((x) => { const p = x.trim().split(/\s+/); if (p[0]) d[p[0].toLowerCase()] = p.slice(1); });
    const iss = [];
    const sc = d['script-src'] || d['default-src'];
    if (!sc) iss.push('tidak ada script-src/default-src');
    else {
      if (sc.includes("'unsafe-inline'") && !sc.some((x) => /^'(nonce|sha)/.test(x))) iss.push("script-src mengizinkan 'unsafe-inline'");
      if (sc.includes("'unsafe-eval'")) iss.push("'unsafe-eval' diizinkan");
      if (sc.some((x) => x === '*' || x === 'http:' || x === 'data:')) iss.push('sumber script terlalu longgar (*, http:, data:)');
    }
    if (!d['object-src'] && !d['default-src']) iss.push('object-src tidak dibatasi');
    return iss;
  }

  function auditHeaders(h, https) {
    const checks = [];
    const add = (key, label, weight, status, got, note) => checks.push({ key, label, weight, status, got: got || '', note: note || '' });

    const csp = h['content-security-policy'];
    if (!csp) add('csp', 'Content-Security-Policy', 25, 'missing');
    else { const i = cspIssues(csp); add('csp', 'Content-Security-Policy', 25, i.length ? 'warn' : 'ok', csp, i.join('; ')); }

    if (https) {
      const v = h['strict-transport-security'];
      if (!v) add('hsts', 'Strict-Transport-Security', 20, 'missing');
      else {
        const age = +((/max-age=(\d+)/i.exec(v) || [])[1] || 0);
        add('hsts', 'Strict-Transport-Security', 20, age >= 15552000 ? 'ok' : 'warn', v, age >= 15552000 ? '' : 'max-age kurang dari 180 hari');
      }
    }

    const xfo = h['x-frame-options'];
    const fa = /frame-ancestors/i.test(csp || '');
    if (!xfo && !fa) add('xfo', 'X-Frame-Options / frame-ancestors', 10, 'missing');
    else add('xfo', 'X-Frame-Options / frame-ancestors', 10, 'ok', xfo || 'via CSP frame-ancestors');

    const x = h['x-content-type-options'];
    add('xcto', 'X-Content-Type-Options', 10, !x ? 'missing' : /nosniff/i.test(x) ? 'ok' : 'warn', x, /nosniff/i.test(x || '') ? '' : 'seharusnya nosniff');

    const rp = h['referrer-policy'];
    add('rp', 'Referrer-Policy', 10, !rp ? 'missing' : /unsafe-url|^no-referrer-when-downgrade$/i.test(rp) ? 'warn' : 'ok', rp, /unsafe-url|^no-referrer-when-downgrade$/i.test(rp || '') ? 'terlalu longgar' : '');

    const pp = h['permissions-policy'] || h['feature-policy'];
    add('pp', 'Permissions-Policy', 10, pp ? 'ok' : 'missing', pp);
    add('coop', 'Cross-Origin-Opener-Policy', 5, h['cross-origin-opener-policy'] ? 'ok' : 'missing', h['cross-origin-opener-policy']);
    add('corp', 'Cross-Origin-Resource-Policy', 5, h['cross-origin-resource-policy'] ? 'ok' : 'missing', h['cross-origin-resource-policy']);
    add('coep', 'Cross-Origin-Embedder-Policy', 5, h['cross-origin-embedder-policy'] ? 'ok' : 'missing', h['cross-origin-embedder-policy']);

    const total = checks.reduce((a, c) => a + c.weight, 0);
    const earned = checks.reduce((a, c) => a + (c.status === 'ok' ? c.weight : c.status === 'warn' ? c.weight / 2 : 0), 0);
    const score = Math.round((earned / total) * 100);
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

    const leaks = [];
    if (h.server && /\d/.test(h.server)) leaks.push({ header: 'Server', value: h.server });
    for (const k of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) if (h[k]) leaks.push({ header: k, value: h[k] });
    return { score, grade, checks, leaks };
  }

  const TRACK = /^(_ga|_gid|_gat|_fbp|_fbc|_gcl|__utm|_hj|_clck|_clsk|fr$|IDE$|NID$|_pk_|ajs_|mp_)/i;
  const SESS = /sess|auth|token|jwt|sid$|login/i;

  function analyzeCookies(list, https) {
    return list.map((c) => {
      const issues = [];
      if (https && !c.secure) issues.push('tanpa Secure');
      if (!c.httpOnly && SESS.test(c.name)) issues.push('cookie sesi tanpa HttpOnly');
      if (c.sameSite === 'no_restriction' && !c.secure) issues.push('SameSite=None tanpa Secure');
      if (c.sameSite === 'unspecified') issues.push('SameSite tidak diset');
      const type = TRACK.test(c.name) ? 'Tracking' : SESS.test(c.name) ? 'Sesi' : 'Fungsional';
      const days = c.session || !c.expirationDate ? null : Math.round((c.expirationDate * 1000 - Date.now()) / 864e5);
      return { name: c.name, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, days, type, issues };
    });
  }

  function classifyTP(tp, mainHost, tpCats) {
    const main = regDomain(mainHost);
    const rows = []; let first = 0;
    for (const host in tp || {}) {
      if (regDomain(host) === main) { first += tp[host].c; continue; }
      const hit = tpCats.find(([, re]) => re.test(host));
      rows.push({ host, count: tp[host].c, types: tp[host].t, ip: tp[host].ip, cat: hit ? hit[0] : 'Lainnya' });
    }
    rows.sort((a, b) => b.count - a.count);
    return { rows, firstPartyRequests: first };
  }

  function buildFindings(r) {
    const f = []; const add = (sev, text) => f.push({ sev, text });
    if (!r.https) add('high', 'Halaman dimuat lewat HTTP (tanpa enkripsi).');
    for (const c of r.audit.checks) {
      if (c.status === 'missing') add(c.weight >= 20 ? 'med' : 'low', `Header ${c.label} tidak ada.`);
      if (c.status === 'warn') add('low', `${c.label}: ${c.note}.`);
    }
    r.audit.leaks.forEach((l) => add('low', `Header membocorkan teknologi/versi: ${l.header}: ${l.value}`));
    const bad = r.cookies.filter((c) => c.issues.some((i) => i !== 'SameSite tidak diset'));
    if (bad.length) add('med', `${bad.length} cookie dengan flag keamanan lemah.`);
    const rc = r.recon || {};
    (rc.secrets || []).forEach((s) => add('high', `Kemungkinan secret terekspos di kode (${s.type}): ${s.masked}`));
    (rc.forms || []).filter((x) => x.insecure).forEach((x) => add('high', `Form mengirim ke HTTP: ${x.action}`));
    if (rc.mixed && rc.mixed.length) add('med', `${rc.mixed.length} resource HTTP dimuat di halaman HTTPS (mixed content).`);
    if (rc.noSri) add('low', `${rc.noSri} script pihak ketiga tanpa Subresource Integrity.`);
    (rc.forms || []).filter((x) => x.hasPassword && !x.hasCsrf && x.method === 'post').forEach(() => add('low', 'Form password tanpa token CSRF terlihat.'));
    if (rc.emails && rc.emails.length) add('info', `${rc.emails.length} alamat email terlihat di halaman.`);
    if (rc.comments && rc.comments.length) add('info', `${rc.comments.length} komentar HTML ditemukan (periksa isinya).`);
    return f;
  }

  function toMarkdown(r) {
    const L = [];
    L.push(`# ReconLens Report: ${r.host}`, '', `- URL: ${r.url}`, `- IP: ${r.ip || '-'}`, `- Status: ${r.status || '-'}`, `- Waktu: ${r.time}`, `- Security header: **${r.audit.grade}** (${r.audit.score}/100)`, '');
    L.push('## Temuan');
    r.findings.length ? r.findings.forEach((x) => L.push(`- [${x.sev.toUpperCase()}] ${x.text}`)) : L.push('- Tidak ada temuan.');
    L.push('', '## Teknologi');
    r.tech.forEach((t) => L.push(`- ${t.name}${t.version ? ' ' + t.version : ''} (${t.cat})`));
    L.push('', '## Security Header', '| Header | Status | Nilai/Catatan |', '|---|---|---|');
    r.audit.checks.forEach((c) => L.push(`| ${c.label} | ${c.status} | ${(c.note || c.got || '').replace(/\|/g, '\\|').slice(0, 120)} |`));
    L.push('', '## Cookie', '| Nama | Tipe | Secure | HttpOnly | SameSite | Masalah |', '|---|---|---|---|---|---|');
    r.cookies.forEach((c) => L.push(`| ${c.name} | ${c.type} | ${c.secure} | ${c.httpOnly} | ${c.sameSite} | ${c.issues.join(', ')} |`));
    L.push('', '## Pihak Ketiga');
    r.tp.rows.forEach((t) => L.push(`- ${t.host} (${t.cat}, ${t.count} req)`));
    const rc = r.recon || {};
    L.push('', '## Recon Halaman');
    L.push(`- Email: ${(rc.emails || []).join(', ') || '-'}`, `- Telepon: ${(rc.phones || []).join(', ') || '-'}`);
    L.push(`- Form: ${(rc.forms || []).length}`, `- Endpoint dari JS: ${(rc.endpoints || []).length}`);
    (rc.endpoints || []).forEach((e) => L.push(`  - ${e}`));
    (rc.wellKnown || []).forEach((w) => L.push(`- ${w.path}: HTTP ${w.status}`));
    if (r.intel) L.push('', '## Domain Intel', '```json', JSON.stringify(r.intel, null, 2), '```');
    return L.join('\n');
  }

  const api = { regDomain, hmap, detect, cspIssues, auditHeaders, analyzeCookies, classifyTP, buildFindings, toMarkdown };
  if (typeof module !== 'undefined') module.exports = api; else root.A = api;
})(typeof self !== 'undefined' ? self : this);
