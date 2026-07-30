#!/usr/bin/env node
'use strict';
// kimi-claude-auth SessionStart hook: make sure the OAuth proxy is running on
// 127.0.0.1:8320 (KIMI_CLAUDE_AUTH_PORT overrides). If /health answers, print a
// one-line status and exit; otherwise spawn proxy/proxy.js detached (stdout/stderr
// appended to proxy/proxy.log next to the script) and poll until it comes up.
// SessionStart stdout is injected into the session context, so output is kept to
// one short line (plus a config hint when ~/.kimi-code/config.toml has no
// provider pointing at this proxy — we never edit the user's config ourselves).
// Always exit 0.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

const PORT = String(parseInt(process.env.KIMI_CLAUDE_AUTH_PORT || '8320', 10));
const HEALTH_URL = `http://127.0.0.1:${PORT}/health`;
const PLUGIN_ROOT = process.env.KIMI_PLUGIN_ROOT || path.join(__dirname, '..');
const PROXY_SCRIPT = path.join(PLUGIN_ROOT, 'proxy', 'proxy.js');
const LOG_FILE = path.join(PLUGIN_ROOT, 'proxy', 'proxy.log');
const KIMI_CONFIG = path.join(os.homedir(), '.kimi-code', 'config.toml');

function healthy(cb) {
  let done = false;
  const finish = (ok, body) => { if (!done) { done = true; cb(ok, body); } };
  const req = http.get(HEALTH_URL, { timeout: 500 }, (res) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => finish(res.statusCode === 200, Buffer.concat(chunks).toString('utf-8')));
  });
  req.on('timeout', () => { req.destroy(); finish(false); });
  req.on('error', () => finish(false));
}

function statusLine(body) {
  try {
    const h = JSON.parse(body);
    const active = (h.accounts || []).find((a) => a.source === h.activeSource) || h.accounts?.[0];
    if (!active) return `kimi-claude-auth: proxy up on 127.0.0.1:${PORT} but NO Claude Code credentials found — run \`claude\` once to log in.`;
    const state = active.valid ? `token valid until ${active.expiresAt}` : 'token EXPIRED (proxy will try to refresh)';
    return `kimi-claude-auth: proxy up on 127.0.0.1:${PORT} (v${h.version}, source: ${active.source}, ${state})`;
  } catch {
    return `kimi-claude-auth: proxy up on 127.0.0.1:${PORT}`;
  }
}

function configHint() {
  let text = '';
  try { text = fs.readFileSync(KIMI_CONFIG, 'utf-8'); } catch { /* no config yet */ }
  if (text.includes(`127.0.0.1:${PORT}`)) return null;
  return [
    'kimi-claude-auth: ~/.kimi-code/config.toml has no provider pointing at this proxy. Add:',
    '',
    '  [providers.claude]',
    '  type = "anthropic"',
    `  base_url = "http://127.0.0.1:${PORT}"`,
    '  api_key = "oauth-via-proxy"   # placeholder; the proxy replaces it',
    '',
    '  [models."claude-sonnet-4-6"]',
    '  provider = "claude"',
    '  model = "claude-sonnet-4-6"',
    '  max_context_size = 200000',
  ].join('\n');
}

function report(body) {
  console.log(statusLine(body));
  const hint = configHint();
  if (hint) console.log(hint);
}

function main() {
  // Consume the hook payload from stdin first.
  try { fs.readFileSync(0, 'utf-8'); } catch {}

  healthy((ok, body) => {
    if (ok) {
      report(body);
      return process.exit(0);
    }
    try {
      const out = fs.openSync(LOG_FILE, 'a');
      const child = spawn(process.execPath, [PROXY_SCRIPT], {
        detached: true,
        stdio: ['ignore', out, out],
        env: { ...process.env },
      });
      child.unref();
    } catch {}
    // Poll up to 8s for the proxy to come up; exit either way (hook timeout is 15s).
    const deadline = Date.now() + 8000;
    const poll = () => {
      healthy((up, upBody) => {
        if (up) {
          report(upBody);
          return process.exit(0);
        }
        if (Date.now() >= deadline) {
          console.log(`kimi-claude-auth: proxy did not come up on 127.0.0.1:${PORT}; see ${LOG_FILE}`);
          return process.exit(0);
        }
        setTimeout(poll, 150);
      });
    };
    poll();
  });
}

try { main(); } catch { process.exit(0); }
