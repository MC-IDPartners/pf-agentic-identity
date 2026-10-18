'use strict';

const api = {
  async get(path) {
    const res = await fetch(`/api${path}`, { headers: { accept: 'application/json' } });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(json.error || res.statusText), json);
    return json;
  },
  async send(method, path, body) {
    const res = await fetch(`/api${path}`, {
      method,
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(json.error || res.statusText), json);
    return json;
  },
  post(path, body) { return api.send('POST', path, body); },
  del(path) { return api.send('DELETE', path); },
};

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );

const pill = (status) => `<span class="pill ${esc(status)}">${esc(status)}</span>`;

function when(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    day: 'numeric', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

/** Marks the current page in the masthead and shows the control-plane mode. */
async function chrome() {
  const here = location.pathname;
  document.querySelectorAll('.masthead nav a').forEach((a) => {
    const href = a.getAttribute('href');
    const match = href === '/' ? here === '/' : here.startsWith(href);
    if (match) a.setAttribute('aria-current', 'page');
  });

  const plane = document.querySelector('.plane');
  if (!plane) return;
  try {
    const cfg = await api.get('/config');
    if (cfg.raidiamMode === 'live') {
      plane.textContent = 'Live control plane';
      plane.classList.add('is-live');
    } else {
      plane.textContent = 'Control plane · mock';
    }
    window.__cfg = cfg;
  } catch {
    plane.textContent = 'Control plane · unknown';
  }
}

function notice(container, message, kind = 'error') {
  if (!container) return;
  container.className = `notice ${kind}`;
  container.innerHTML = esc(message);
  container.classList.remove('hidden');
}

document.addEventListener('DOMContentLoaded', chrome);
