const assert = require('node:assert/strict');
const A = require('../analysis.js');
const { SIGS, TP_CATS } = require('../signatures.js');

const h = A.hmap([
  { n: 'Server', v: 'nginx/1.24.0' }, { n: 'X-Powered-By', v: 'PHP/8.2.1' },
  { n: 'Content-Security-Policy', v: "default-src 'self'; script-src 'self' 'unsafe-inline'" },
  { n: 'Strict-Transport-Security', v: 'max-age=31536000' }
]);

// Tech detection + version extraction
const tech = A.detect({ headers: h, meta: { generator: 'WordPress 6.4' }, cookies: ['_ga', 'PHPSESSID'],
  resources: ['https://x.com/wp-content/a.js', 'https://code.jquery.com/jquery-3.7.1.min.js'], html: '', globals: { 'jQuery.fn.jquery': '3.7.1' } }, SIGS, TP_CATS);
const names = Object.fromEntries(tech.map((t) => [t.name, t.version]));
assert.equal(names['Nginx'], '1.24.0');
assert.equal(names['PHP'], '8.2.1');
assert.equal(names['WordPress'], '6.4');
assert.equal(names['jQuery'], '3.7.1');
assert.ok('Google Analytics' in names);

// Security header audit
const audit = A.auditHeaders(h, true);
assert.ok(audit.score < 50 && audit.grade === 'F');
assert.equal(audit.checks.find((c) => c.key === 'csp').status, 'warn');
assert.equal(audit.checks.find((c) => c.key === 'hsts').status, 'ok');
assert.equal(audit.leaks.length, 2);
assert.equal(A.auditHeaders({}, false).checks.some((c) => c.key === 'hsts'), false);

// Registrable domain heuristics
assert.equal(A.regDomain('www.kampus.ac.id'), 'kampus.ac.id');
assert.equal(A.regDomain('a.b.example.com'), 'example.com');
assert.equal(A.regDomain('192.168.1.1'), '192.168.1.1');

// Third-party classification
const tp = A.classifyTP({ 'www.x.com': { c: 3, t: ['script'] }, 'www.google-analytics.com': { c: 2, t: ['script'] } }, 'x.com', TP_CATS);
assert.equal(tp.rows.length, 1);
assert.equal(tp.rows[0].cat, 'Analytics');
assert.equal(tp.firstPartyRequests, 3);

// Cookie analysis
const [ck] = A.analyzeCookies([{ name: 'sessionid', secure: false, httpOnly: false, sameSite: 'unspecified', session: true }], true);
assert.equal(ck.type, 'Sesi');
assert.ok(ck.issues.includes('tanpa Secure') && ck.issues.includes('cookie sesi tanpa HttpOnly'));

// Findings + report
const r = { host: 'x', url: 'u', https: true, audit, cookies: [ck], recon: { secrets: [{ type: 'AWS Access Key', masked: 'AKIA12…XYZ' }] }, tech, tp, time: 't' };
r.findings = A.buildFindings(r);
assert.ok(r.findings.some((f) => f.sev === 'high'));
assert.match(A.toMarkdown(r), /# ReconLens Report/);

console.log('All tests passed');
