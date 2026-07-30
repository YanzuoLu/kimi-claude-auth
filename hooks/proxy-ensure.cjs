#!/usr/bin/env node
'use strict';
// kimi-claude-auth proxy-ensure hook, wired to both SessionStart and
// UserPromptSubmit: make sure a proxy of THIS plugin version is running on
// 127.0.0.1:8320 (KIMI_CLAUDE_AUTH_PORT overrides). Missing or stale proxies are
// (re-)spawned from proxy/proxy.js, detached, with stdout/stderr appended to
// proxy/proxy.log next to the script.
//
// Version matters because the proxy is detached: after a plugin upgrade the old
// process keeps serving old code until something kills it. /health reports the
// running version and pid; pid is the only usable handle, since the proxy sets
// process.title and `pkill -f` on macOS matches the (now hidden) argv instead.
//
// Hook stdout is injected into the session context. SessionStart prints one
// status line (plus a config hint when ~/.kimi-code/config.toml has no provider
// pointing at this proxy — we never edit the user's config ourselves).
// UserPromptSubmit runs before every single message, so it stays silent unless
// the proxy is genuinely unreachable, and skips the probe entirely when another
// run confirmed health less than THROTTLE_MS ago. Always exit 0.

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
const STAMP_FILE = path.join(PLUGIN_ROOT, 'proxy', '.health-stamp');
const KIMI_CONFIG = path.join(os.homedir(), '.kimi-code', 'config.toml');
const THROTTLE_MS = 10_000;

// The proxy reads its own version from the same manifest, so these only differ
// when the running process was started from an older copy of the plugin.
const WANT_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(PLUGIN_ROOT, 'kimi.plugin.json'), 'utf-8')).version || null;
  } catch {
    return null;
  }
})();

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

function parseHealth(body) {
  try {
    const h = JSON.parse(body);
    return h && typeof h === 'object' ? h : null;
  } catch {
    return null;
  }
}

const isStale = (health) => !!(WANT_VERSION && health && health.version && health.version !== WANT_VERSION);

// Ask the old proxy to go away, then wait for the port to actually free up so
// the replacement does not lose the race to EADDRINUSE.
function killProxy(pid, cb) {
  try {
    process.kill(pid, 'SIGTERM');
  } catch {
    return cb();
  }
  const deadline = Date.now() + 3000;
  const wait = () => {
    healthy((up) => {
      if (!up || Date.now() >= deadline) return cb();
      setTimeout(wait, 100);
    });
  };
  wait();
}

function startProxy(cb) {
  try {
    const out = fs.openSync(LOG_FILE, 'a');
    const child = spawn(process.execPath, [PROXY_SCRIPT], {
      detached: true,
      stdio: ['ignore', out, out],
      env: { ...process.env },
    });
    child.unref();
  } catch {}
  // Poll up to 8s for the proxy to come up; give up either way (hook timeout is 15s).
  const deadline = Date.now() + 8000;
  const poll = () => {
    healthy((up, upBody) => {
      if (up) return cb(true, upBody);
      if (Date.now() >= deadline) return cb(false, null);
      setTimeout(poll, 150);
    });
  };
  poll();
}

function checkedRecently() {
  try {
    return Date.now() - fs.statSync(STAMP_FILE).mtimeMs < THROTTLE_MS;
  } catch {
    return false;
  }
}

function main() {
  // Consume the hook payload from stdin first; it tells us which event we are.
  let payload = {};
  try { payload = JSON.parse(fs.readFileSync(0, 'utf-8')) || {}; } catch {}
  const silent = payload.hook_event_name === 'UserPromptSubmit';

  if (silent && checkedRecently()) return process.exit(0);

  const done = (body) => {
    try { fs.writeFileSync(STAMP_FILE, new Date().toISOString()); } catch {}
    if (!silent) report(body);
    process.exit(0);
  };

  healthy((ok, body) => {
    const health = ok ? parseHealth(body) : null;
    if (ok && !isStale(health)) return done(body);

    const restart = () => {
      startProxy((up, upBody) => {
        if (up) return done(upBody);
        console.log(`kimi-claude-auth: proxy did not come up on 127.0.0.1:${PORT}; see ${LOG_FILE}`);
        process.exit(0);
      });
    };

    if (!ok) return restart();

    // Stale proxy: replace it. Without a pid there is nothing safe to kill.
    if (typeof health.pid !== 'number') {
      console.log(
        `kimi-claude-auth: proxy on 127.0.0.1:${PORT} runs v${health.version} but this plugin is v${WANT_VERSION}, and it reports no pid — restart it manually.`,
      );
      return process.exit(0);
    }
    if (!silent) {
      console.log(`kimi-claude-auth: replacing stale proxy v${health.version} (pid ${health.pid}) with v${WANT_VERSION}`);
    }
    killProxy(health.pid, restart);
  });
}

try { main(); } catch { process.exit(0); }
