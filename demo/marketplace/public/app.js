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
  const nav = document.querySelector('.masthead nav');
  if (nav && !nav.querySelector('a[href="/objectives"]')) {
    nav.insertAdjacentHTML('beforeend', '<a href="/objectives">Objectives</a>');
  }
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
      const a = cfg.auth || {};
      plane.classList.add('is-live');
      plane.innerHTML = a.signedIn
        ? `Live control plane<br><span class="session">Raidiam: ${esc(a.who || 'signed in')} · <a href="#" id="signout">sign out</a></span>`
        : `Live control plane<br><a class="session signin" href="/auth/login">Sign in to Raidiam</a>`;
      const out = document.getElementById('signout');
      if (out) out.addEventListener('click', async (e) => { e.preventDefault(); await api.post('/auth/logout'); location.reload(); });
      const q = new URLSearchParams(location.search);
      if (q.get('signInError')) notice(document.getElementById('notice'), `Raidiam sign-in failed: ${q.get('signInError')}`);
      if (q.get('signedIn')) notice(document.getElementById('notice'), `Signed in to Raidiam as ${a.who || 'you'}.`, 'ok');
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
