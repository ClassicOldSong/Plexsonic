/* Copyright Yukino Song, SudoMaker Ltd.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function optionCard({ label, description, value, name, checked = false }) {
  return `
    <label class="card-option">
      <input type="radio" name="${escapeHtml(name)}" value="${escapeHtml(value)}" ${checked ? 'checked' : ''} required />
      <div class="card-content">
        <span class="card-title">${escapeHtml(label)}</span>
        ${description ? `<span class="card-desc">${escapeHtml(description)}</span>` : ''}
      </div>
    </label>
  `;
}

function actionLinks(links = []) {
  if (links.length === 0) {
    return '';
  }

  const content = links
    .map(
      (link) =>
        `<a class="link-button" href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>`,
    )
    .join('');

  return `<div class="links">${content}</div>`;
}

export function pageTemplate({ title, body, notice = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg-body: #f3f4f6;
      --bg-panel: #ffffff;
      --text-main: #1f2937;
      --text-muted: #6b7280;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --danger: #dc2626;
      --danger-bg: #fef2f2;
      --border: #e5e7eb;
      --font-sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text-main);
      font-family: var(--font-sans);
      background-color: var(--bg-body);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px;
      line-height: 1.5;
    }

    main {
      width: 100%;
      max-width: 520px;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 40px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
    }

    h1 {
      margin: 0 0 24px;
      font-weight: 700;
      font-size: 1.875rem;
      letter-spacing: -0.025em;
      color: var(--text-main);
      text-align: center;
    }

    p {
      margin: 0 0 24px;
      color: var(--text-muted);
      font-size: 1rem;
      text-align: left;
    }

    .notice {
      background: var(--danger-bg);
      color: var(--danger);
      border: 1px solid var(--danger);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 24px;
      font-size: 0.9rem;
      text-align: center;
    }

    form {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    label {
      display: flex;
      flex-direction: column;
      gap: 8px;
      font-weight: 500;
      font-size: 0.95rem;
      color: var(--text-main);
    }

    input:not([type="radio"]) {
      appearance: none;
      background-color: #fff;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 1rem;
      color: var(--text-main);
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }

    input:not([type="radio"]):focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
    }

    button, .link-button {
      appearance: none;
      border: none;
      border-radius: 6px;
      background-color: var(--primary);
      color: #fff;
      font-size: 1rem;
      font-weight: 500;
      padding: 12px 20px;
      cursor: pointer;
      width: 100%;
      text-decoration: none;
      display: inline-flex;
      justify-content: center;
      align-items: center;
      transition: background-color 0.15s ease;
    }

    button:hover, .link-button:hover {
      background-color: var(--primary-hover);
    }

    .muted {
      color: var(--text-muted);
      font-size: 0.875rem;
      text-align: center;
      margin-top: 16px;
    }

    .links {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      justify-content: center;
      margin-top: 24px;
    }

    .links form {
        width: 100%;
        margin-top: 0;
    }
    
    /* Make link-buttons inside .links slightly less dominant if needed, 
       but keeping them consistent for now. */

    .card-grid {
      display: grid;
      gap: 12px;
    }

    .card-option {
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 12px;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      background: #fff;
      cursor: pointer;
      transition: border-color 0.15s ease, background-color 0.15s ease;
    }

    .card-option input[type="radio"] {
      width: 18px;
      height: 18px;
      accent-color: var(--primary);
      margin: 0;
    }

    .card-content {
       display: flex;
       flex-direction: column;
    }

    .card-title {
      font-weight: 600;
      font-size: 1rem;
      color: var(--text-main);
    }

    .card-desc {
        font-size: 0.85rem;
        color: var(--text-muted);
    }

    .code, .endpoint, .status {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      background: #f3f4f6;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      margin: 8px 0;
      word-break: break-all;
    }

    .test-output {
      white-space: pre-wrap;
      overflow: auto;
      max-height: 300px;
      word-break: break-word;
    }

    .test-grid {
      display: flex;
      flex-direction: column;
      gap: 16px;
      margin-top: 24px;
    }

    @media (max-width: 600px) {
      main { padding: 24px; border: none; box-shadow: none; background: transparent; }
      body { background: var(--bg-panel); padding: 0; }
    }
  </style>
</head>
<body>
  <main>
    ${notice ? `<div class="notice">${escapeHtml(notice)}</div>` : ''}
    ${body}
  </main>
</body>
</html>`;
}

export function signupPage(notice = '') {
  return pageTemplate({
    title: 'Create Subsonic Account',
    notice,
    body: `
      <h1>Create account</h1>
      <p>Create the local Subsonic account first. Plex linking starts right after signup.</p>
      <form method="post" action="/signup">
        <label>Username
          <input name="username" autocomplete="username" minlength="3" maxlength="32" required />
        </label>
        <label>Password
          <input name="password" type="password" autocomplete="new-password" minlength="8" required />
        </label>
        <button type="submit">Create account</button>
      </form>
      ${actionLinks([{ href: '/login', label: 'Sign in' }])}
    `,
  });
}

export function loginPage(notice = '') {
  return pageTemplate({
    title: 'Sign In',
    notice,
    body: `
      <h1>Sign in</h1>
      <p>Use your local Subsonic credentials.</p>
      <form method="post" action="/login">
        <label>Username
          <input name="username" autocomplete="username" required />
        </label>
        <label>Password
          <input name="password" type="password" autocomplete="current-password" required />
        </label>
        <button type="submit">Sign in</button>
      </form>
      ${actionLinks([{ href: '/signup', label: 'Create account' }])}
    `,
  });
}

export function linkPlexPage(username, notice = '') {
  return pageTemplate({
    title: 'Link Plex',
    notice,
    body: `
      <h1>Link Plex</h1>
      <p>Signed in as <strong>${escapeHtml(username)}</strong>.</p>
      <p>Start Plex login in a separate page. When authorization is finished, that page will close automatically.</p>
      <form
        method="post"
        action="/link/plex/start"
        target="plex-auth-popup"
        onsubmit="return openPlexAuthPopup('plex-auth-popup');"
      >
        <button type="submit">Link Plex account</button>
      </form>
      <div class="links">
        <form method="post" action="/logout">
          <button type="submit">Sign out</button>
        </form>
      </div>
      <script>
        function openPlexAuthPopup(name) {
          const width = 540;
          const height = 760;
          const dualScreenLeft = window.screenLeft ?? window.screenX ?? 0;
          const dualScreenTop = window.screenTop ?? window.screenY ?? 0;
          const viewportWidth = window.innerWidth || document.documentElement.clientWidth || screen.width;
          const viewportHeight = window.innerHeight || document.documentElement.clientHeight || screen.height;
          const left = Math.max(0, Math.round(dualScreenLeft + (viewportWidth - width) / 2));
          const top = Math.max(0, Math.round(dualScreenTop + (viewportHeight - height) / 2));
          window.open(
            'about:blank',
            name,
            'popup,width=' + width + ',height=' + height + ',left=' + left + ',top=' + top + ',resizable=yes,scrollbars=yes',
          );
          return true;
        }
      </script>
    `,
  });
}

export function linkedPlexPage({
  username,
  serverName = null,
  libraryName = null,
  notice = '',
}) {
  const statusLines = [
    `<p><strong>User:</strong> ${escapeHtml(username)}</p>`,
    `<p><strong>Plex link:</strong> Connected</p>`,
    `<p><strong>Server:</strong> ${serverName ? escapeHtml(serverName) : 'Not selected yet'}</p>`,
    `<p><strong>Music library:</strong> ${libraryName ? escapeHtml(libraryName) : 'Not selected yet'}</p>`,
  ].join('');

  return pageTemplate({
    title: 'Plex Linked',
    notice,
    body: `
      <h1>Plex linked</h1>
      ${statusLines}
      <div class="links">
        <a class="link-button" href="/link/plex/server">Select server</a>
        <a class="link-button" href="/link/plex/library">Select library</a>
        <a class="link-button" href="/test">Test page</a>
      </div>
      <div class="links">
        <form
          method="post"
          action="/link/plex/start"
          target="plex-auth-popup"
          onsubmit="return openPlexAuthPopup('plex-auth-popup');"
        >
          <button type="submit">Re-authorize Plex</button>
        </form>
        <form method="post" action="/account/plex/unlink">
          <button type="submit">Unlink Plex</button>
        </form>
        <form method="post" action="/logout">
          <button type="submit">Sign out</button>
        </form>
      </div>
      <form method="post" action="/account/password" style="margin-top: 48px; border-top: 1px solid var(--border); padding-top: 24px;">
        <h2 style="font-size: 1.25rem; margin-bottom: 20px;">Change Password</h2>
        <label>Current password
          <input name="currentPassword" type="password" autocomplete="current-password" required />
        </label>
        <label>New password
          <input name="newPassword" type="password" autocomplete="new-password" minlength="8" required />
        </label>
        <label>Confirm new password
          <input name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required />
        </label>
        <button type="submit">Update password</button>
      </form>
      <script>
        function openPlexAuthPopup(name) {
          const width = 540;
          const height = 760;
          const dualScreenLeft = window.screenLeft ?? window.screenX ?? 0;
          const dualScreenTop = window.screenTop ?? window.screenY ?? 0;
          const viewportWidth = window.innerWidth || document.documentElement.clientWidth || screen.width;
          const viewportHeight = window.innerHeight || document.documentElement.clientHeight || screen.height;
          const left = Math.max(0, Math.round(dualScreenLeft + (viewportWidth - width) / 2));
          const top = Math.max(0, Math.round(dualScreenTop + (viewportHeight - height) / 2));
          window.open(
            'about:blank',
            name,
            'popup,width=' + width + ',height=' + height + ',left=' + left + ',top=' + top + ',resizable=yes,scrollbars=yes',
          );
          return true;
        }
      </script>
    `,
  });
}

export function plexPinPage({ authUrl, sid, phase }) {
  return pageTemplate({
    title: 'Authorize Plex',
    body: `
      <h1>Authorize Plex</h1>
      <p id="hint">Finishing Plex authorization.</p>
      <div id="status" class="status">Preparing auth flow...</div>
      <div class="links">
        <a id="manualLink" class="link-button" href="${escapeHtml(authUrl)}" rel="noopener noreferrer">Open Plex Auth</a>
      </div>
      <script>
        const sid = ${JSON.stringify(sid)};
        const authUrl = ${JSON.stringify(authUrl)};
        const phase = ${JSON.stringify(phase)};
        const statusEl = document.getElementById('status');
        const hintEl = document.getElementById('hint');
        const manualLinkEl = document.getElementById('manualLink');

        function closeOrShowMessage(nextUrl) {
          let closed = false;
          if (window.opener && !window.opener.closed) {
            try {
              window.opener.location.assign(nextUrl);
            } catch {}
          }
          try {
            window.close();
            closed = window.closed;
          } catch {}

          if (!closed) {
            hintEl.textContent = 'Plex linked. You can close this page now.';
            statusEl.textContent = 'Plex authorization completed.';
            manualLinkEl.style.display = 'none';
          }
        }

        async function poll() {
          try {
            const res = await fetch('/link/plex/poll?sid=' + encodeURIComponent(sid), { cache: 'no-store' });
            const data = await res.json();
            if (data.status === 'linked') {
              statusEl.textContent = 'Plex linked. Attempting to close...';
              closeOrShowMessage(data.next || '/link/plex/server');
              return;
            }
            if (data.status === 'expired') {
              hintEl.textContent = 'Plex authorization expired.';
              statusEl.textContent = 'Please close this page and start again.';
              return;
            }
            statusEl.textContent = 'Waiting for Plex authorization...';
          } catch (_error) {
            statusEl.textContent = 'Polling failed, retrying...';
          }
          setTimeout(poll, 2500);
        }

        if (phase === 'launch') {
          hintEl.textContent = 'Opening Plex login...';
          statusEl.textContent = 'If nothing happens, click "Open Plex Auth".';
          setTimeout(() => {
            window.location.assign(authUrl);
          }, 150);
        } else {
          hintEl.textContent = 'Authorization complete. Verifying link...';
          statusEl.textContent = 'Checking Plex link status...';
          manualLinkEl.style.display = 'none';
          poll();
        }
      </script>
    `,
  });
}

export function plexServerPage({ servers, selectedMachineId = null, notice = '' }) {
  const options = servers
    .map((server) =>
      optionCard({
        name: 'serverChoice',
        value: server.encodedChoice,
        checked: selectedMachineId ? selectedMachineId === server.machineId : false,
        label: server.name,
        description: `${server.baseUrl}`,
      }),
    )
    .join('');

  return pageTemplate({
    title: 'Select Plex Server',
    notice,
    body: `
      <h1>Select Plex Server</h1>
      <p>Choose which Plex Media Server this account should use.</p>
      ${
        servers.length
          ? `<form method="post" action="/link/plex/server"><div class="card-grid">${options}</div><button type="submit">Save server</button></form>`
          : `<p>No servers found. Confirm the Plex account has a reachable server on your LAN.</p>`
      }
      ${actionLinks([{ href: '/link/plex', label: 'Back' }])}
    `,
  });
}

export function plexLibraryPage({ sections, selectedSectionId = null, notice = '' }) {
  const options = sections
    .map((section) =>
      optionCard({
        name: 'libraryChoice',
        value: section.encodedChoice,
        checked: selectedSectionId ? selectedSectionId === section.id : false,
        label: section.title
      }),
    )
    .join('');

  return pageTemplate({
    title: 'Select Music Library',
    notice,
    body: `
      <h1>Select Music Library</h1>
      <p>Pick the Plex music section to expose through Subsonic endpoints.</p>
      ${
        sections.length
          ? `<form method="post" action="/link/plex/library"><div class="card-grid">${options}</div><button type="submit">Save library</button></form>`
          : `<p>No music sections found on this server.</p>`
      }
      ${actionLinks([{ href: '/link/plex/server', label: 'Back' }])}
    `,
  });
}

export function testPage({ username }) {
  const restBase = '/rest';

  return pageTemplate({
    title: 'Test Page',
    body: `
      <h1>Test page</h1>
      <p>The bridge is ready for this account.</p>
      <p><strong>Username:</strong> ${escapeHtml(username)}</p>
      <p><strong>Subsonic API base:</strong></p>
      <div class="endpoint">${escapeHtml(restBase)}</div>

      <div class="test-grid">
        <label>Manual test password
          <input id="pw" type="password" placeholder="Enter local account password" />
        </label>
        <div class="links">
          <button type="button" onclick="runTest('ping.view')">Ping</button>
          <button type="button" onclick="runTest('getArtists.view')">List artists</button>
        </div>
        <pre id="testResult" class="status test-output">Run a test endpoint to inspect JSON output.</pre>
      </div>

      ${actionLinks([{ href: '/link/plex/server', label: 'Change server' }, { href: '/link/plex/library', label: 'Change library' }])}

      <script>
        const username = ${JSON.stringify(username)};
        async function runTest(endpoint) {
          const password = document.getElementById('pw').value;
          const out = document.getElementById('testResult');
          if (!password) {
            out.textContent = 'Enter password first.';
            return;
          }
          const params = new URLSearchParams({
            u: username,
            p: password,
            c: 'web',
            v: '1.16.1',
            f: 'json',
          });
          const url = '/rest/' + endpoint + '?' + params.toString();
          out.textContent = 'Requesting ' + url + ' ...';
          try {
            const res = await fetch(url, {
              cache: 'no-store',
              headers: {
                Accept: 'application/json',
              },
            });
            const text = await res.text();
            out.textContent = formatResponse(text);
          } catch (err) {
            out.textContent = 'Request failed: ' + err.message;
          }
        }

        function formatResponse(text) {
          const trimmed = String(text || '').trim();
          if (!trimmed) {
            return '';
          }

          try {
            return JSON.stringify(JSON.parse(trimmed), null, 2);
          } catch {
            return trimmed;
          }
        }
      </script>
    `,
  });
}

export function encodeChoicePayload(payload) {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

export function decodeChoicePayload(value) {
  try {
    return JSON.parse(Buffer.from(String(value), 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}
