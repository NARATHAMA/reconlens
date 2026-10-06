# 🔍 ReconLens

[![CI](https://github.com/NARATHAMA/reconlens/actions/workflows/ci.yml/badge.svg)](https://github.com/NARATHAMA/reconlens/actions)
![Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Chrome extension for **passive information gathering**. It profiles every site you open: technology stack, security headers, cookies, third-party domains, page-level recon, and optional domain intelligence. All analysis runs locally in your browser.

🇮🇩 [Baca dalam Bahasa Indonesia](README.id.md)

<p align="center"><img src="docs/screenshot-summary.png" width="360"> <img src="docs/screenshot-headers.png" width="360"></p>

## Features

| Module | What it does |
|---|---|
| **Tech fingerprinting** | ~80 signatures (servers, CDN/WAF, CMS, JS frameworks, analytics) matched against headers, cookies, meta tags, script URLs, DOM, and JS globals, with version extraction |
| **Security header audit** | Scores CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP (A–F), flags weak CSP and version-leaking headers |
| **Cookie analyzer** | Secure / HttpOnly / SameSite checks, expiry, tracking vs. session vs. functional classification |
| **Third-party map** | Every external domain the page contacts, categorized (analytics, ads, CDN, ...) |
| **Page recon** | Meta tags, forms, emails/phones, HTML comments, API endpoints extracted from JS, masked possible-secret detection, mixed content, missing SRI, `robots.txt` / `sitemap.xml` / `security.txt` |
| **Domain intel** *(opt-in)* | DNS, SPF/DMARC, RDAP registrar data, TLS certificate history and subdomains via crt.sh |
| **Export** | JSON and Markdown reports |

## Install

```bash
git clone https://github.com/NARATHAMA/reconlens.git
```
1. Open `chrome://extensions` and enable **Developer mode**
2. Click **Load unpacked** and select the cloned folder
3. Open any site, **reload the page once**, then click the ReconLens icon

No build step required.

## Architecture

```
background.js   service worker: records response headers & third-party hosts per tab (webRequest, observe-only)
popup.js        UI + page collector injected via chrome.scripting (isolated + MAIN world)
analysis.js     pure logic (detection, audit, cookies, findings, reports), unit-tested in Node
signatures.js   technology signature database, easy to extend
```

Design choices: Manifest V3, least-privilege permissions, state persisted in `chrome.storage.session` so the service worker can sleep safely, pure analysis logic separated from Chrome APIs for testability.

### Add a signature
```js
{ n: 'MyTool', c: 'Category', h: { server: 'mytool/([\\d.]+)' }, s: ['cdn\\.mytool\\.com'], js: ['MyTool.version'] }
```

## Privacy

- No telemetry, no accounts, no remote servers owned by this project.
- Network requests beyond normal browsing: (1) fetching well-known files from the *current* site (toggleable), (2) Domain Intel to `dns.google`, `rdap.org`, `crt.sh` **only when you click the button**.

## Development

```bash
npm run lint
npm test
```

## Responsible use

ReconLens is passive by design: it observes what your browser already loaded and requests only standard public files. It performs no scanning, fuzzing, or exploitation. Use it on sites you own or are authorized to assess. Detected "possible secrets" are heuristics and may be false positives.

## Roadmap

- [ ] Per-domain history and side-panel dashboard
- [ ] Larger signature set (import from open datasets)
- [ ] Diff between scans
- [ ] Options page and domain allow/deny list

## License

MIT, see [LICENSE](LICENSE).
