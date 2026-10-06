const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const TABS = ['Ringkasan', 'Teknologi', 'Header', 'Cookie', 'Pihak-3', 'Recon', 'Domain'];
let R = null, cur = 'Ringkasan';

// ---------- Fungsi yang diinjeksi ke halaman (harus self-contained) ----------
async function collect(opts) {
  const q = (s) => [...document.querySelectorAll(s)];
  const host = location.hostname, https = location.protocol === 'https:';
  const meta = {};
  q('meta').forEach((m) => { const k = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv'); if (k) meta[k.toLowerCase()] = m.content; });
  const scriptEls = q('script[src]');
  const scripts = scriptEls.map((s) => s.src);
  const css = q('link[rel~=stylesheet]').map((l) => l.href);
  const hostOf = (u) => { try { return new URL(u).hostname; } catch { return ''; } };
  const links = q('a[href]').map((a) => a.href).filter((h) => /^https?:/.test(h));
  const internal = [...new Set(links.filter((h) => hostOf(h) === host))];
  const external = [...new Set(links.filter((h) => hostOf(h) !== host))];
  const forms = q('form').map((f) => {
    const inputs = [...f.elements].filter((e) => e.name || e.type).slice(0, 40).map((e) => ({ name: e.name, type: e.type }));
    return {
      action: f.action, method: (f.method || 'get').toLowerCase(), inputs,
      hasPassword: inputs.some((i) => i.type === 'password'),
      hasCsrf: inputs.some((i) => i.type === 'hidden' && /csrf|token|nonce|authenticity/i.test(i.name)),
      insecure: https && /^http:/i.test(f.action)
    };
  });
  const comments = [];
  const tw = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
  while (tw.nextNode() && comments.length < 30) { const t = tw.currentNode.nodeValue.trim(); if (t.length > 3) comments.push(t.slice(0, 200)); }
  const text = (document.body ? document.body.innerText : '').slice(0, 200000);
  const emails = [...new Set([...(text.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g) || []), ...q('a[href^="mailto:"]').map((a) => a.href.slice(7).split('?')[0])])].slice(0, 30);
  const phones = [...new Set([...(text.match(/(?:\+62|\b0)8\d{2}[\s-]?\d{3,4}[\s-]?\d{3,5}\b/g) || []), ...q('a[href^="tel:"]').map((a) => a.href.slice(4))])].slice(0, 20);
  const iframes = q('iframe[src]').map((i) => i.src);
  const mixed = https ? [...scripts, ...css, ...iframes, ...q('img[src]').map((i) => i.src)].filter((u) => /^http:/i.test(u)) : [];
  const noSri = scriptEls.filter((s) => hostOf(s.src) !== host && !s.integrity).length;

  // Endpoint & secret dari inline script + script same-origin
  const sources = q('script:not([src])').map((s) => s.textContent || '');
  for (const u of scripts.filter((u) => hostOf(u) === host).slice(0, 8)) {
    try { const r = await fetch(u, { credentials: 'omit' }); sources.push((await r.text()).slice(0, 400000)); } catch {}
  }
  const endpoints = new Set();
  const epRe = /["'`](\/(?:api|v\d|rest|graphql|wp-json|ajax|admin|auth|oauth|login|user|users)[\w\-./{}?=&%]*)["'`]/gi;
  const absRe = /https?:\/\/[^"'\s<>\\)]+\/(?:api|graphql|rest|v\d)\b[^"'\s<>\\)]*/gi;
  const secretDefs = [['AWS Access Key', /AKIA[0-9A-Z]{16}/g], ['Google API Key', /AIza[0-9A-Za-z\-_]{35}/g], ['Private Key', /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g], ['Slack Token', /xox[baprs]-[0-9A-Za-z-]{10,}/g], ['GitHub Token', /gh[pousr]_[A-Za-z0-9]{36}/g], ['Stripe Live Key', /sk_live_[0-9a-zA-Z]{20,}/g]];
  const secrets = [];
  for (const src of sources) {
    let m; epRe.lastIndex = 0; absRe.lastIndex = 0;
    while ((m = epRe.exec(src)) && endpoints.size < 80) endpoints.add(m[1]);
    while ((m = absRe.exec(src)) && endpoints.size < 80) endpoints.add(m[0]);
    for (const [type, re] of secretDefs) { const mm = src.match(re); if (mm) secrets.push({ type, masked: mm[0].slice(0, 6) + '…' + mm[0].slice(-3) }); }
  }

  const wellKnown = [];
  if (opts.wellKnown) {
    for (const p of ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/humans.txt']) {
      try {
        const ac = new AbortController(); const to = setTimeout(() => ac.abort(), 5000);
        const r = await fetch(p, { credentials: 'omit', signal: ac.signal }); clearTimeout(to);
        const t = await r.text();
        if (r.ok && !/^\s*<(!doctype|html)/i.test(t)) wellKnown.push({ path: p, status: r.status, preview: t.slice(0, 1500) });
      } catch {}
    }
  }
  return {
    title: document.title, meta, scripts, css, html: document.documentElement.outerHTML.slice(0, 200000),
    internalCount: internal.length, external: external.slice(0, 100), internal: internal.slice(0, 100),
    forms, comments, emails, phones, iframes, mixed, noSri,
    inlineScripts: sources.length, endpoints: [...endpoints], secrets, wellKnown
  };
}

function probeGlobals(paths) {
  const out = {};
  for (const p of paths) {
    try {
      let v = window;
      for (const k of p.split('.')) v = v[k];
      if (v !== undefined && v !== null) out[p] = typeof v === 'string' || typeof v === 'number' ? String(v) : true;
    } catch {}
  }
  return out;
}

// ---------- Analisis ----------
async function analyze() {
  $('#view').textContent = 'Menganalisis…';
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https?:/.test(tab.url || '')) { $('#view').innerHTML = '<p class="muted">Halaman ini tidak bisa dianalisis (hanya http/https).</p>'; return; }
  const url = new URL(tab.url), https = url.protocol === 'https:';
  const st = await chrome.runtime.sendMessage({ type: 'getState', tabId: tab.id });
  const cookies = await chrome.cookies.getAll({ url: tab.url });
  let dom = null, globals = {}, err = '';
  try {
    [{ result: dom }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collect, args: [{ wellKnown: $('#optWk').checked }] });
    const paths = [...new Set(SIGS.flatMap((s) => s.js || []))];
    [{ result: globals }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, world: 'MAIN', func: probeGlobals, args: [paths] });
  } catch (e) { err = String(e.message || e); }
  const headers = st ? A.hmap(st.headers) : {};
  const d = dom || { meta: {}, scripts: [], css: [], html: '', forms: [], comments: [], emails: [], phones: [], endpoints: [], secrets: [], wellKnown: [], mixed: [], external: [], internal: [] };
  const tech = A.detect({ headers, meta: d.meta, cookies: cookies.map((c) => c.name), resources: [...d.scripts, ...d.css], html: d.html, globals: globals || {} }, SIGS, TP_CATS);
  R = {
    url: tab.url, host: url.hostname, https, ip: st?.ip, status: st?.statusCode ?? st?.status, time: new Date().toISOString(),
    hasHeaders: !!st, err, title: d.title, headers, rawHeaders: st?.headers || [],
    audit: A.auditHeaders(headers, https), tech, cookies: A.analyzeCookies(cookies, https),
    tp: A.classifyTP(st?.tp, url.hostname, TP_CATS), recon: d, intel: null
  };
  R.findings = A.buildFindings(R);
  const cached = (await chrome.storage.local.get('intel:' + A.regDomain(url.hostname)))['intel:' + A.regDomain(url.hostname)];
  if (cached && Date.now() - cached.ts < 864e5) R.intel = cached.data;
  $('#site').textContent = url.hostname;
  render();
}

// ---------- Domain intel (opt-in; mengirim nama domain ke dns.google, rdap.org, crt.sh) ----------
async function runIntel() {
  const dom = A.regDomain(R.host), btn = $('#intelBtn');
  btn.disabled = true; btn.textContent = 'Memproses…';
  const get = async (u, ms = 15000, h) => { const ac = new AbortController(); const t = setTimeout(() => ac.abort(), ms); try { const r = await fetch(u, { signal: ac.signal, headers: h }); if (!r.ok) throw new Error('HTTP ' + r.status); return await r.json(); } finally { clearTimeout(t); } };
  const dns = async (name, type) => { try { const j = await get(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, 8000, { accept: 'application/dns-json' }); return (j.Answer || []).map((a) => a.data); } catch { return []; } };
  const out = { domain: dom, fetched: new Date().toISOString(), dns: {}, errors: [] };
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'];
  const [rec, dmarc, rdap, crt] = await Promise.all([
    Promise.all(types.map((t) => dns(dom, t))), dns('_dmarc.' + dom, 'TXT'),
    get('https://rdap.org/domain/' + dom).catch((e) => { out.errors.push('RDAP: ' + e.message); return null; }),
    get('https://crt.sh/?output=json&q=' + encodeURIComponent('%.' + dom), 25000).catch((e) => { out.errors.push('crt.sh: ' + e.message); return null; })
  ]);
  types.forEach((t, i) => (out.dns[t] = rec[i]));
  out.dns.DMARC = dmarc;
  out.spf = out.dns.TXT.some((t) => /v=spf1/i.test(t));
  out.dmarc = dmarc.some((t) => /v=DMARC1/i.test(t));
  if (rdap) {
    const ev = (a) => (rdap.events || []).find((e) => e.eventAction === a)?.eventDate;
    const reg = (rdap.entities || []).find((e) => (e.roles || []).includes('registrar'));
    out.rdap = { registrar: reg?.vcardArray?.[1]?.find((x) => x[0] === 'fn')?.[3], created: ev('registration'), expires: ev('expiration'), updated: ev('last changed'), status: rdap.status, nameservers: (rdap.nameservers || []).map((n) => n.ldhName) };
  }
  if (Array.isArray(crt)) {
    const names = new Set();
    crt.forEach((c) => String(c.name_value).split('\n').forEach((n) => names.add(n.trim().toLowerCase().replace(/^\*\./, ''))));
    const latest = crt.filter((c) => String(c.name_value).toLowerCase().includes(R.host)).sort((a, b) => (b.not_after || '').localeCompare(a.not_after || ''))[0] || crt[0];
    out.certs = { total: crt.length, subdomains: [...names].sort().slice(0, 150), subdomainCount: names.size, latest: latest && { issuer: latest.issuer_name, notBefore: latest.not_before, notAfter: latest.not_after } };
  }
  R.intel = out;
  await chrome.storage.local.set({ ['intel:' + dom]: { ts: Date.now(), data: out } });
  render();
}

// ---------- Render ----------
const tbl = (head, rows) => `<table><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</table>`;
const gradeColor = (g) => ({ A: '#16a34a', B: '#65a30d', C: '#d97706', D: '#ea580c', F: '#dc2626' }[g]);
const list = (a, f = esc) => (a && a.length ? `<ul>${a.map((x) => `<li>${f(x)}</li>`).join('')}</ul>` : '<p class="muted">Tidak ada.</p>');

const VIEWS = {
  Ringkasan() {
    const r = R, rc = r.recon;
    return `${r.hasHeaders ? '' : '<p class="warn">Header tidak tersedia: muat ulang halaman agar ReconLens bisa merekam header & pihak ketiga.</p>'}
    ${r.err ? `<p class="warn">Sebagian analisis gagal: ${esc(r.err)}</p>` : ''}
    <div><span class="grade" style="background:${gradeColor(r.audit.grade)}">${r.audit.grade}</span> <b>${r.audit.score}/100</b> skor security header
    <div class="muted">${esc(r.title || '')}<br>IP: ${esc(r.ip || '-')} · HTTP ${esc(r.status || '-')} · ${r.https ? 'HTTPS' : 'HTTP'}</div></div>
    <div class="grid"><div class="stat"><b>${r.tech.length}</b>teknologi</div><div class="stat"><b>${r.cookies.length}</b>cookie</div><div class="stat"><b>${r.tp.rows.length}</b>domain pihak-3</div>
    <div class="stat"><b>${rc.forms.length}</b>form</div><div class="stat"><b>${rc.endpoints.length}</b>endpoint JS</div><div class="stat"><b>${rc.emails.length}</b>email</div></div>
    <h4>Temuan (${r.findings.length})</h4>${r.findings.length ? `<ul>${r.findings.map((f) => `<li><span class="sev ${f.sev}">${f.sev}</span>${esc(f.text)}</li>`).join('')}</ul>` : '<p class="ok">Tidak ada temuan.</p>'}`;
  },
  Teknologi() {
    if (!R.tech.length) return '<p class="muted">Tidak ada teknologi yang terdeteksi.</p>';
    const by = {}; R.tech.forEach((t) => (by[t.cat] = by[t.cat] || []).push(t));
    return Object.keys(by).sort().map((c) => `<h4>${esc(c)}</h4>${by[c].map((t) => `<span class="tag">${esc(t.name)}${t.version ? ' ' + esc(t.version) : ''}</span>`).join('')}`).join('');
  },
  Header() {
    const a = R.audit;
    return `<h4>Audit security header</h4>${tbl(['Header', 'Status', 'Catatan'], a.checks.map((c) => [esc(c.label), `<b class="${c.status}">${c.status}</b>`, esc(c.note || c.got).slice(0, 160)]))}
    <h4>Kebocoran informasi</h4>${list(a.leaks, (l) => `${esc(l.header)}: ${esc(l.value)}`)}
    <h4>Semua header respons</h4>${R.rawHeaders.length ? tbl(['Nama', 'Nilai'], R.rawHeaders.map((h) => [esc(h.n), esc(h.v).slice(0, 200)])) : '<p class="muted">Muat ulang halaman untuk merekam header.</p>'}`;
  },
  Cookie() {
    if (!R.cookies.length) return '<p class="muted">Tidak ada cookie.</p>';
    return tbl(['Nama', 'Tipe', 'Flag', 'Masalah'], R.cookies.map((c) => [esc(c.name), esc(c.type), `${c.secure ? 'Secure ' : ''}${c.httpOnly ? 'HttpOnly ' : ''}${esc(c.sameSite)}${c.days != null ? ` · ${c.days}h` : ' · sesi'}`, `<span class="warn">${esc(c.issues.join(', '))}</span>`]));
  },
  'Pihak-3'() {
    const t = R.tp;
    if (!t.rows.length) return `<p class="muted">Belum ada pihak ketiga terekam. ${R.hasHeaders ? '' : 'Muat ulang halaman.'}</p>`;
    return `<p class="muted">${t.firstPartyRequests} request first-party · ${t.rows.length} domain pihak ketiga</p>` + tbl(['Domain', 'Kategori', 'Req', 'Tipe'], t.rows.map((x) => [esc(x.host), esc(x.cat), x.count, esc(x.types.join(', '))]));
  },
  Recon() {
    const r = R.recon;
    return `<h4>Meta</h4>${tbl(['Nama', 'Isi'], Object.entries(r.meta).slice(0, 25).map(([k, v]) => [esc(k), esc(v).slice(0, 150)]))}
    <h4>Kontak</h4>${list([...r.emails, ...r.phones])}
    <h4>Form (${r.forms.length})</h4>${r.forms.length ? tbl(['Action', 'Method', 'Input'], r.forms.map((f) => [esc(f.action), esc(f.method) + (f.hasPassword ? ' 🔑' : ''), esc(f.inputs.map((i) => i.name || i.type).join(', ')).slice(0, 100)])) : '<p class="muted">Tidak ada.</p>'}
    <h4>Endpoint dari JavaScript (${r.endpoints.length})</h4>${list(r.endpoints)}
    <h4>Possible secrets</h4>${list(r.secrets.map((s) => `${s.type}: ${s.masked}`))}
    <h4>File well-known</h4>${r.wellKnown.length ? r.wellKnown.map((w) => `<b>${esc(w.path)}</b> (HTTP ${w.status})<pre>${esc(w.preview)}</pre>`).join('') : '<p class="muted">Tidak ada / dinonaktifkan.</p>'}
    <h4>Komentar HTML (${r.comments.length})</h4>${list(r.comments)}
    <h4>Link</h4><p class="muted">${r.internalCount} internal · ${r.external.length} eksternal · ${r.iframes.length} iframe · ${r.inlineScripts} script dianalisis</p>`;
  },
  Domain() {
    const i = R.intel;
    const btn = `<button id="intelBtn" class="pri">${i ? 'Perbarui' : 'Jalankan'} Domain Intel</button>`;
    const note = `<p class="muted">Mengirim nama domain <b>${esc(A.regDomain(R.host))}</b> ke dns.google, rdap.org, dan crt.sh. Hanya dijalankan saat Anda menekan tombol; hasil di-cache 24 jam.</p>`;
    if (!i) return note + btn;
    const dnsRows = Object.entries(i.dns).filter(([, v]) => v.length).map(([k, v]) => [k, esc(v.join('\n')).replace(/\n/g, '<br>')]);
    return `${note}${btn}${i.errors.length ? `<p class="warn">${esc(i.errors.join(' | '))}</p>` : ''}
    <h4>Email security</h4><p>SPF: <b class="${i.spf ? 'ok' : 'missing'}">${i.spf ? 'ada' : 'tidak ada'}</b> · DMARC: <b class="${i.dmarc ? 'ok' : 'missing'}">${i.dmarc ? 'ada' : 'tidak ada'}</b></p>
    <h4>DNS</h4>${dnsRows.length ? tbl(['Tipe', 'Nilai'], dnsRows) : '<p class="muted">Kosong.</p>'}
    <h4>RDAP / WHOIS</h4>${i.rdap ? tbl(['Field', 'Nilai'], [['Registrar', esc(i.rdap.registrar || '-')], ['Dibuat', esc(i.rdap.created || '-')], ['Kedaluwarsa', esc(i.rdap.expires || '-')], ['Diubah', esc(i.rdap.updated || '-')], ['Status', esc((i.rdap.status || []).join(', '))], ['Nameserver', esc((i.rdap.nameservers || []).join(', '))]]) : '<p class="muted">Tidak tersedia (TLD mungkin tidak mendukung RDAP).</p>'}
    <h4>Sertifikat TLS (crt.sh)</h4>${i.certs ? `<p>${i.certs.total} sertifikat · ${i.certs.subdomainCount} nama unik${i.certs.latest ? `<br>Terbaru: ${esc(i.certs.latest.issuer)}<br>Berlaku ${esc(i.certs.latest.notBefore)} → ${esc(i.certs.latest.notAfter)}` : ''}</p>${list(i.certs.subdomains)}` : '<p class="muted">Tidak tersedia.</p>'}`;
  }
};

function render() {
  $('#tabs').innerHTML = TABS.map((t) => `<button class="${t === cur ? 'on' : ''}" data-t="${t}">${t}</button>`).join('');
  $('#view').innerHTML = VIEWS[cur]();
  $('#intelBtn')?.addEventListener('click', runIntel);
}
$('#tabs').addEventListener('click', (e) => { const t = e.target.dataset.t; if (t) { cur = t; render(); } });
$('#reload').addEventListener('click', analyze);

function download(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const slug = () => `reconlens-${R.host}-${new Date().toISOString().slice(0, 10)}`;
$('#expJson').addEventListener('click', () => R && download(slug() + '.json', JSON.stringify(R, (k, v) => (k === 'html' ? undefined : v), 2), 'application/json'));
$('#expMd').addEventListener('click', () => R && download(slug() + '.md', A.toMarkdown(R), 'text/markdown'));

analyze();
