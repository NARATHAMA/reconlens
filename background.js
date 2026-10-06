// Service worker: merekam header respons & domain pihak ketiga per tab (pasif, hanya observasi).
const mem = new Map();
const timers = new Map();
const key = (id) => 'tab' + id;

async function load(id) {
  if (!mem.has(id)) {
    const r = await chrome.storage.session.get(key(id));
    if (!mem.has(id)) mem.set(id, r[key(id)] || null);
  }
  return mem.get(id);
}

function scheduleFlush(id) {
  clearTimeout(timers.get(id));
  timers.set(id, setTimeout(() => {
    const s = mem.get(id);
    if (s) chrome.storage.session.set({ [key(id)]: s });
  }, 500));
}

chrome.webRequest.onHeadersReceived.addListener((d) => {
  if (d.tabId < 0) return;
  if (d.type === 'main_frame') {
    mem.set(d.tabId, {
      url: d.url, status: d.statusCode, ip: d.ip || null, time: Date.now(),
      headers: (d.responseHeaders || []).map((h) => ({ n: h.name, v: h.value || '' })),
      tp: {}
    });
    scheduleFlush(d.tabId);
    return;
  }
  (async () => {
    const s = await load(d.tabId);
    if (!s) return;
    let host;
    try { host = new URL(d.url).hostname; } catch { return; }
    const e = (s.tp[host] = s.tp[host] || { c: 0, t: [], ip: d.ip || null });
    e.c++;
    if (!e.t.includes(d.type)) e.t.push(d.type);
    scheduleFlush(d.tabId);
  })();
}, { urls: ['http://*/*', 'https://*/*'] }, ['responseHeaders']);

chrome.runtime.onMessage.addListener((msg, _s, send) => {
  if (msg?.type === 'getState') {
    load(msg.tabId).then((s) => send(s || null));
    return true;
  }
});

chrome.tabs.onRemoved.addListener((id) => {
  mem.delete(id);
  clearTimeout(timers.get(id));
  chrome.storage.session.remove(key(id));
});
