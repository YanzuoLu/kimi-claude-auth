#!/usr/bin/env node
'use strict';
// kimi-claude-auth proxy: lets Kimi Code CLI reuse the local Claude Code OAuth
// subscription credentials to call the Anthropic API (claude-* models) — no API
// key, no separate OAuth login.
//
// Listens on 127.0.0.1:<port> (default 8320, KIMI_CLAUDE_AUTH_PORT overrides).
// Point Kimi Code's anthropic provider base_url at it. Every non-/health request
// is treated as an Anthropic API call: the JSON body is reshaped to look like a
// genuine Claude Code request (billing header + identity system prompt, cache
// breakpoints, metadata.user_id, cch attestation signature), the headers are
// rebuilt from scratch (OAuth Bearer + beta flags + local-agent identity +
// stainless + X-Claude-Code-Session-Id), and the request is forwarded to
// https://api.anthropic.com<original path>. Responses stream back untouched
// (SSE-safe, never buffered on the success path).
//
// Credentials come from the macOS Keychain ("Claude Code-credentials*" entries)
// or ~/.claude/.credentials.json, are cached in memory for 30s, refreshed via
// POST https://claude.ai/v1/oauth/token when within 60s of expiry, and written
// back to storage (refresh tokens rotate on every refresh — write-back is
// mandatory). Falls back to invoking the `claude` CLI when direct refresh fails.
//
// The request-shaping pipeline is ported (behavior-faithful, code rewritten)
// from opencode-claude-auth (MIT, fork of griffinmartin/opencode-claude-auth).
// One deliberate deviation: the mcp_ tool-name prefixing is skipped — Kimi Code
// already uses PascalCase tool names, and the response stream is passed through
// byte-for-byte. One log line per proxied request on stdout.

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const { execFileSync, execSync } = require('node:child_process');

// ---------------------------------------------------------------------------
// Constants / config
// ---------------------------------------------------------------------------

const VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'kimi.plugin.json'), 'utf8')).version || 'unknown';
  } catch {
    return 'unknown';
  }
})();

const HOST = '127.0.0.1';
const PORT = parseInt(process.env.KIMI_CLAUDE_AUTH_PORT || '8320', 10);
const UPSTREAM_HOST = 'api.anthropic.com';

// Claude Code version fingerprints sent in headers and the billing header.
const CC_VERSION = '2.1.165';
const AGENT_SDK_VERSION = '0.3.165';
const CLIENT_VERSION = '1.11187.4';

const BASE_BETAS = [
  'claude-code-20250219',
  'oauth-2025-04-20',
  'interleaved-thinking-2025-05-14',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'mid-conversation-system-2026-04-07',
  'advanced-tool-use-2025-11-20',
];
const LONG_CONTEXT_BETAS = ['context-1m-2025-08-07', 'interleaved-thinking-2025-05-14'];
const EXTENDED_CACHE_TTL_BETA = 'extended-cache-ttl-2025-04-11';

// First-match-wins, substring against the lowercased model id.
const MODEL_OVERRIDES = {
  haiku: { exclude: ['interleaved-thinking-2025-05-14'], disableEffort: true },
  '4-6': { add: ['effort-2025-11-24'] },
  '4-7': { add: ['effort-2025-11-24'] },
};

const OAUTH_TOKEN_URL = 'https://claude.ai/v1/oauth/token';
const OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';

const CREDENTIAL_CACHE_TTL_MS = 30_000; // in-memory credential cache
const EXPIRY_MARGIN_MS = 60_000; // refresh when within 60s of expiry
const DEFAULT_MAX_RETRY_DELAY_MS = 30_000; // cap for honoring 429/529 retry-after
const MAX_CACHE_BREAKPOINTS = 4; // Anthropic hard limit per request

const SYSTEM_IDENTITY = "You are a Claude agent, built on Anthropic's Claude Agent SDK.";
const BILLING_PREFIX = 'x-anthropic-billing-header:';

const START = Date.now();
// Fallback session id for requests that carry no upstream session identifier;
// requests that have one get their own id (see sessionIdFor).
const processSessionId = crypto.randomUUID();
process.title = 'kimi-claude-auth-proxy';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function getMaxRetryDelayMs() {
  const env = process.env.KIMI_CLAUDE_AUTH_MAX_RETRY_MS;
  if (env) {
    const parsed = parseInt(env, 10);
    if (!Number.isNaN(parsed) && parsed > 0) return parsed;
  }
  return DEFAULT_MAX_RETRY_DELAY_MS;
}

// Never print a token; length + masked ends only.
function maskToken(t) {
  if (typeof t !== 'string' || t.length < 12) return '(invalid)';
  return `${t.slice(0, 12)}...${t.slice(-4)} (len=${t.length})`;
}

// ---------------------------------------------------------------------------
// xxHash64 (pure JS, BigInt) + cch billing attestation
// ---------------------------------------------------------------------------

const MASK64 = 0xffffffffffffffffn;
const PRIME64_1 = 0x9e3779b185ebca87n;
const PRIME64_2 = 0xc2b2ae3d27d4eb4fn;
const PRIME64_3 = 0x165667b19e3779f9n;
const PRIME64_4 = 0x85ebca77c2b2ae63n;
const PRIME64_5 = 0x27d4eb2f165667c5n;

const u64 = (v) => v & MASK64;
function rotl64(v, bits) {
  const s = BigInt(bits);
  return u64((v << s) | (v >> (64n - s)));
}
function round64(acc, input) {
  return u64(rotl64(u64(acc + u64(input * PRIME64_2)), 31) * PRIME64_1);
}
function mergeRound64(acc, v) {
  return u64(u64(acc ^ round64(0n, v)) * PRIME64_1 + PRIME64_4);
}
function avalanche64(h) {
  h ^= h >> 33n;
  h = u64(h * PRIME64_2);
  h ^= h >> 29n;
  h = u64(h * PRIME64_3);
  h ^= h >> 32n;
  return u64(h);
}

function xxHash64(data, seed) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const length = data.byteLength;
  let offset = 0;
  let hash;

  if (length >= 32) {
    let v1 = u64(seed + PRIME64_1 + PRIME64_2);
    let v2 = u64(seed + PRIME64_2);
    let v3 = u64(seed);
    let v4 = u64(seed - PRIME64_1);
    const limit = length - 32;
    while (offset <= limit) {
      v1 = round64(v1, view.getBigUint64(offset, true)); offset += 8;
      v2 = round64(v2, view.getBigUint64(offset, true)); offset += 8;
      v3 = round64(v3, view.getBigUint64(offset, true)); offset += 8;
      v4 = round64(v4, view.getBigUint64(offset, true)); offset += 8;
    }
    hash = u64(rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18));
    hash = mergeRound64(hash, v1);
    hash = mergeRound64(hash, v2);
    hash = mergeRound64(hash, v3);
    hash = mergeRound64(hash, v4);
  } else {
    hash = u64(seed + PRIME64_5);
  }

  hash = u64(hash + BigInt(length));

  while (offset + 8 <= length) {
    hash = u64(hash ^ round64(0n, view.getBigUint64(offset, true)));
    hash = u64(rotl64(hash, 27) * PRIME64_1 + PRIME64_4);
    offset += 8;
  }
  if (offset + 4 <= length) {
    hash = u64(hash ^ u64(BigInt(view.getUint32(offset, true)) * PRIME64_1));
    hash = u64(rotl64(hash, 23) * PRIME64_2 + PRIME64_3);
    offset += 4;
  }
  while (offset < length) {
    hash = u64(hash ^ u64(BigInt(data[offset]) * PRIME64_5));
    hash = u64(rotl64(hash, 11) * PRIME64_1);
    offset++;
  }
  return avalanche64(hash);
}

// Billing attestation: the billing system block carries a `cch=00000`
// placeholder that must be replaced, just before sending, with
// xxHash64(fullBody, seed) & 0xfffff (5 hex chars).
const CCH_SEED = u64(0x4d659218e32a3268n);
const CCH_PLACEHOLDER = Buffer.from('cch=00000');
const BILLING_MARKER = Buffer.from('"system":[{"type":"text","text":"x-anthropic-billing-header:');
const CCH_SEARCH_WINDOW = 150;

function patchCch(body) {
  const markerIdx = body.indexOf(BILLING_MARKER);
  if (markerIdx === -1) return 'no-billing-header';
  const searchFrom = markerIdx + BILLING_MARKER.length;
  const idx = body.indexOf(CCH_PLACEHOLDER, searchFrom);
  if (idx === -1 || idx - searchFrom > CCH_SEARCH_WINDOW) return 'unanchored';
  const cch = (xxHash64(body, CCH_SEED) & 0xfffffn).toString(16).padStart(5, '0');
  for (let i = 0; i < 5; i++) body[idx + 4 + i] = cch.charCodeAt(i);
  return 'patched';
}

// ---------------------------------------------------------------------------
// Billing header construction (matches Claude Code's K19-style derivation)
// ---------------------------------------------------------------------------

const BILLING_SALT = '59cf53e54c78';

function extractFirstUserMessageText(messages) {
  const userMsg = (messages || []).find((m) => m && m.role === 'user');
  if (!userMsg) return '';
  const content = userMsg.content;
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    const textBlock = content.find((b) => b && b.type === 'text');
    if (textBlock && typeof textBlock.text === 'string') return textBlock.text;
  }
  return '';
}

function computeVersionSuffix(messageText, version) {
  const sampled = [4, 7, 20].map((i) => (i < messageText.length ? messageText[i] : '0')).join('');
  return crypto.createHash('sha256').update(`${BILLING_SALT}${sampled}${version}`).digest('hex').slice(0, 3);
}

function buildBillingHeaderValue(messages, version) {
  const suffix = computeVersionSuffix(extractFirstUserMessageText(messages), version);
  return (
    'x-anthropic-billing-header: ' +
    `cc_version=${version}.${suffix}; ` +
    'cc_entrypoint=local-agent; ' +
    'cch=00000;'
  );
}

// ---------------------------------------------------------------------------
// Beta flags (model-aware)
// ---------------------------------------------------------------------------

// Session-level per-model exclusions, learned from long-context error responses.
const excludedBetas = new Map();

function getExcludedBetas(modelId) {
  return excludedBetas.get(modelId) || new Set();
}
function addExcludedBeta(modelId, beta) {
  const set = excludedBetas.get(modelId) || new Set();
  set.add(beta);
  excludedBetas.set(modelId, set);
}
function getNextBetaToExclude(modelId) {
  const excluded = getExcludedBetas(modelId);
  for (const beta of LONG_CONTEXT_BETAS) {
    if (!excluded.has(beta)) return beta;
  }
  return null;
}
function isLongContextError(body) {
  return (
    body.includes('Extra usage is required for long context requests') ||
    body.includes('long context beta is not yet available') ||
    body.includes("You're out of extra usage")
  );
}

function normalize1mModelId(modelId) {
  if (/\[1m\]$/i.test(modelId)) return { modelId: modelId.slice(0, -4), requested1m: true };
  if (/-1m$/i.test(modelId)) return { modelId: modelId.slice(0, -3), requested1m: true };
  return { modelId, requested1m: false };
}
const normalizeModelId = (modelId) => normalize1mModelId(modelId).modelId;

function modelHasDefault1mContext(modelId) {
  const lower = normalizeModelId(modelId).toLowerCase();
  return (
    /^claude-(?:fable|mythos)-5(?:-\d{8})?$/.test(lower) ||
    /^claude-opus-4-[78](?:-fast)?(?:-\d{8})?$/.test(lower)
  );
}
function modelSupports1mBetaOptIn(modelId) {
  const lower = normalizeModelId(modelId).toLowerCase();
  return /^claude-(?:opus|sonnet)-4-6(?:-fast)?(?:-\d{8})?$/.test(lower);
}
function shouldAdd1mContextBeta(modelId) {
  const normalized = normalize1mModelId(modelId);
  if (!modelSupports1mBetaOptIn(normalized.modelId)) return false;
  if (modelHasDefault1mContext(normalized.modelId)) return false;
  return normalized.requested1m || process.env.ANTHROPIC_ENABLE_1M_CONTEXT === 'true';
}

function getModelOverride(modelId) {
  const lower = modelId.toLowerCase();
  for (const [pattern, override] of Object.entries(MODEL_OVERRIDES)) {
    if (lower.includes(pattern)) return override;
  }
  return null;
}

function getRequiredBetas() {
  return (process.env.ANTHROPIC_BETA_FLAGS || BASE_BETAS.join(','))
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function getModelBetas(modelId, excluded) {
  const normalizedModelId = normalizeModelId(modelId);
  const betas = getRequiredBetas().filter((b) => b !== EXTENDED_CACHE_TTL_BETA);
  const append = (b) => { if (!betas.includes(b)) betas.push(b); };

  // context-1m is OPT-IN only, matching official Claude CLI behavior.
  if (shouldAdd1mContextBeta(modelId)) append(LONG_CONTEXT_BETAS[0]);

  const override = getModelOverride(normalizedModelId);
  if (override) {
    for (const ex of override.exclude || []) {
      const idx = betas.indexOf(ex);
      if (idx !== -1) betas.splice(idx, 1);
    }
    for (const add of override.add || []) {
      if (add !== EXTENDED_CACHE_TTL_BETA) append(add);
    }
  }

  append(EXTENDED_CACHE_TTL_BETA); // always last

  if (excluded && excluded.size > 0) return betas.filter((b) => !excluded.has(b));
  return betas;
}

// ---------------------------------------------------------------------------
// Prompt caching: OAuth defaults to 1h TTL; enforce the 4-breakpoint limit
// ---------------------------------------------------------------------------

function getCacheControl() {
  const override = (process.env.KIMI_CLAUDE_AUTH_CACHE_TTL || '').toLowerCase();
  if (override === '5m' || override === 'none' || override === 'off') {
    return { type: 'ephemeral' };
  }
  return { type: 'ephemeral', ttl: '1h' }; // always OAuth here
}

const cloneCacheControl = (cc) => ({ ...cc });

function countBreakpoints(params) {
  let total = 0;
  for (const tool of params.tools || []) if (tool.cache_control) total++;
  if (Array.isArray(params.system)) {
    for (const block of params.system) if (block.cache_control) total++;
  }
  for (const message of params.messages || []) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) if (block.cache_control) total++;
  }
  return total;
}

function applyToLastTextBlock(blocks, cc) {
  for (let i = blocks.length - 1; i >= 0; i--) {
    if (blocks[i].type === 'text') {
      if (blocks[i].cache_control != null) return false;
      blocks[i] = { ...blocks[i], cache_control: cloneCacheControl(cc) };
      return true;
    }
  }
  for (let i = blocks.length - 1; i >= 0; i--) {
    const t = blocks[i].type;
    if (t === 'thinking' || t === 'redacted_thinking') continue;
    if (blocks[i].cache_control != null) return false;
    blocks[i] = { ...blocks[i], cache_control: cloneCacheControl(cc) };
    return true;
  }
  return false;
}

function applyPromptCaching(params, cc) {
  let used = countBreakpoints(params);
  if (used >= MAX_CACHE_BREAKPOINTS) return;
  let isCCLayout = false;

  if (Array.isArray(params.system) && params.system.length > 0) {
    isCCLayout =
      params.system.length >= 3 &&
      typeof params.system[0].text === 'string' &&
      params.system[0].text.startsWith(BILLING_PREFIX);
    const lastIdx = params.system.length - 1;
    if (params.system[lastIdx].cache_control == null) {
      params.system[lastIdx] = { ...params.system[lastIdx], cache_control: cloneCacheControl(cc) };
      used++;
    }
  }

  const messages = Array.isArray(params.messages) ? params.messages : [];
  const start = isCCLayout ? Math.max(0, messages.length - 1) : Math.max(0, messages.length - 2);
  for (let i = start; i < messages.length && used < MAX_CACHE_BREAKPOINTS; i++) {
    const message = messages[i];
    if (!message) continue;
    if (typeof message.content === 'string') {
      message.content = [{ type: 'text', text: message.content, cache_control: cloneCacheControl(cc) }];
      used++;
    } else if (Array.isArray(message.content) && message.content.length > 0) {
      if (applyToLastTextBlock(message.content, cc)) used++;
    }
  }
}

// Upgrade foreign 5m breakpoints (already present in the incoming body) to the
// 1h OAuth retention; otherwise applyPromptCaching would skip them.
function alignExistingCacheControlTtl(params, cc) {
  const align = (block) => {
    if (block && block.cache_control != null) block.cache_control = cloneCacheControl(cc);
  };
  for (const tool of params.tools || []) align(tool);
  if (Array.isArray(params.system)) for (const block of params.system) align(block);
  for (const message of params.messages || []) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) align(block);
  }
}

function findLastCacheControlIndex(blocks) {
  for (let i = blocks.length - 1; i >= 0; i--) {
    if (blocks[i] && blocks[i].cache_control != null) return i;
  }
  return -1;
}

function enforceCacheControlLimit(params, maxBreakpoints) {
  let excess = countBreakpoints(params) - maxBreakpoints;
  if (excess <= 0) return;
  const systemBlocks = Array.isArray(params.system) ? params.system : [];
  const toolBlocks = params.tools || [];
  const keepSystemIdx = findLastCacheControlIndex(systemBlocks);
  const keepToolIdx = findLastCacheControlIndex(toolBlocks);

  const strip = (blocks, preserveIdx) => {
    for (let i = 0; i < blocks.length && excess > 0; i++) {
      if (i === preserveIdx || !blocks[i].cache_control) continue;
      delete blocks[i].cache_control;
      excess--;
    }
  };
  strip(systemBlocks, keepSystemIdx);
  if (excess > 0) strip(toolBlocks, keepToolIdx);
  if (excess > 0) {
    for (const message of params.messages || []) {
      if (!Array.isArray(message.content)) continue;
      for (const block of message.content) {
        if (excess <= 0) break;
        if (block.cache_control) {
          delete block.cache_control;
          excess--;
        }
      }
    }
  }
  if (excess > 0) strip(systemBlocks, -1);
  if (excess > 0) strip(toolBlocks, -1);
}

// Anthropic requires 1h breakpoints to precede 5m ones; downgrade stragglers.
function normalizeCacheControlTtlOrdering(params) {
  let seenFiveMinute = false;
  const fix = (block) => {
    const cc = block && block.cache_control;
    if (!cc) return;
    if (cc.ttl !== '1h') {
      seenFiveMinute = true;
      return;
    }
    if (seenFiveMinute) {
      const normalized = { ...cc };
      delete normalized.ttl;
      block.cache_control = normalized;
    }
  };
  for (const tool of params.tools || []) fix(tool);
  if (Array.isArray(params.system)) for (const block of params.system) fix(block);
  for (const message of params.messages || []) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) fix(block);
  }
}

function applyCaching(parsed, cc) {
  alignExistingCacheControlTtl(parsed, cc);
  applyPromptCaching(parsed, cc);
  enforceCacheControlLimit(parsed, MAX_CACHE_BREAKPOINTS);
  normalizeCacheControlTtlOrdering(parsed);
}

// ---------------------------------------------------------------------------
// Body transforms
// ---------------------------------------------------------------------------

const isRecord = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

function normalizeSystemEntries(system) {
  if (typeof system === 'string') return [{ type: 'text', text: system }];
  if (!Array.isArray(system)) return [];
  const entries = [];
  for (const entry of system) {
    if (typeof entry === 'string') {
      entries.push({ type: 'text', text: entry });
      continue;
    }
    if (!isRecord(entry) || typeof entry.text !== 'string') continue;
    const type = typeof entry.type === 'string' ? entry.type : 'text';
    if (type !== 'text') continue;
    const { type: _t, text: _x, ...rest } = entry;
    entries.push({ type: 'text', text: entry.text, ...rest });
  }
  return entries;
}

// Canonical Claude Code system layout:
//   [0] billing header  [1] identity  [...] everything else
function buildSystemLayout(parsed) {
  const billingHeader = buildBillingHeaderValue(parsed.messages || [], CC_VERSION);
  const existing = normalizeSystemEntries(parsed.system);
  let agentInstruction;
  const remaining = [];

  for (const entry of existing) {
    if (entry.text.startsWith(BILLING_PREFIX)) continue;
    if (entry.text === SYSTEM_IDENTITY) {
      if (!agentInstruction) agentInstruction = entry;
      continue;
    }
    if (entry.text.startsWith(SYSTEM_IDENTITY)) {
      const rest = entry.text.slice(SYSTEM_IDENTITY.length).replace(/^\n+/, '');
      if (!agentInstruction) {
        const { cache_control: _cc, ...noCc } = entry;
        agentInstruction = { ...noCc, text: SYSTEM_IDENTITY };
      }
      if (rest.length > 0) remaining.push({ ...entry, text: rest });
      continue;
    }
    remaining.push(entry);
  }

  return [
    { type: 'text', text: billingHeader },
    agentInstruction || { type: 'text', text: SYSTEM_IDENTITY },
    ...remaining,
  ];
}

// Move third-party system prompts into the first user message, matching
// omp/Claude Code billing behavior. KIMI_CLAUDE_AUTH_KEEP_SYSTEM=1 opts out.
function applyLegacySystemRelocation(parsed) {
  if (!Array.isArray(parsed.system)) return;
  const kept = [];
  const moved = [];
  for (const entry of parsed.system) {
    const text = entry.text || '';
    if (text.startsWith(BILLING_PREFIX) || text.startsWith(SYSTEM_IDENTITY)) {
      kept.push(entry);
    } else if (text.length > 0) {
      moved.push(text);
    }
  }
  if (moved.length === 0 || !Array.isArray(parsed.messages)) return;
  const firstUser = parsed.messages.find((m) => m.role === 'user');
  if (!firstUser) return;

  parsed.system = kept;
  const prefix = moved.join('\n\n');
  if (typeof firstUser.content === 'string') {
    firstUser.content = `${prefix}\n\n${firstUser.content}`;
  } else if (Array.isArray(firstUser.content)) {
    firstUser.content.unshift({ type: 'text', text: prefix });
  }
}

function shouldRelocateSystem() {
  const keep = process.env.KIMI_CLAUDE_AUTH_KEEP_SYSTEM;
  if (keep === '1' || (keep || '').toLowerCase() === 'true') return false;
  const relocate = process.env.KIMI_CLAUDE_AUTH_RELOCATE_SYSTEM;
  if (relocate) return !['0', 'false', 'off'].includes(relocate.toLowerCase());
  return true;
}

// One proxy process serves every Kimi session on this machine. Anthropic sees
// the session id twice (x-claude-code-session-id and metadata.user_id), so
// collapsing all of them onto one id makes a handful of independent sessions
// look like a single Claude Code client fanning out requests. Keep one stable
// uuid per upstream session instead. Nothing ever tells us a session ended, so
// both maps below are bounded LRUs.
const SESSION_LIMIT = 64;

function lruTouch(map, key) {
  const value = map.get(key);
  if (value === undefined) return undefined;
  map.delete(key); // re-insert so the least recently used key stays first
  map.set(key, value);
  return value;
}

function lruPut(map, key, value) {
  map.delete(key);
  map.set(key, value);
  while (map.size > SESSION_LIMIT) map.delete(map.keys().next().value);
  return value;
}

// metadata.user_id is the only per-conversation identifier we get. Kimi sends
// its bare session id there ("session_<uuid>"); other callers may send a JSON
// blob with a session_id field, so both shapes are accepted. Must be read
// before injectMetadataUserId overwrites the field.
function readUpstreamSessionKey(parsed) {
  const raw = isRecord(parsed) && isRecord(parsed.metadata) ? parsed.metadata.user_id : null;
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    const existing = JSON.parse(raw);
    if (isRecord(existing) && typeof existing.session_id === 'string' && existing.session_id.length > 0) {
      return existing.session_id;
    }
  } catch {
    // non-JSON user_id: the raw string identifies the caller well enough
  }
  return raw;
}

const upstreamSessionIds = new Map(); // upstream session key -> claude-code session uuid

function sessionIdFor(key) {
  if (!key) return processSessionId;
  return lruTouch(upstreamSessionIds, key) || lruPut(upstreamSessionIds, key, crypto.randomUUID());
}

function injectMetadataUserId(parsed) {
  const metadata = isRecord(parsed.metadata) ? parsed.metadata : {};
  const sessionId = sessionIdFor(readUpstreamSessionKey(parsed));
  let existing = {};
  if (typeof metadata.user_id === 'string' && metadata.user_id.length > 0) {
    try {
      const parsedUserId = JSON.parse(metadata.user_id);
      if (isRecord(parsedUserId)) existing = parsedUserId;
    } catch {
      // non-JSON user_id: normalized below
    }
  }
  parsed.metadata = { ...metadata, user_id: JSON.stringify({ ...existing, session_id: sessionId }) };
}

function isThinkingEnabled(thinking) {
  if (!isRecord(thinking)) return false;
  if (thinking.type === 'enabled') return true;
  return thinking.budget_tokens != null || thinking.budget != null;
}

function isInvalidThinkingSignatureError(status, body) {
  return status === 400 && /invalid.{0,40}signature.{0,40}thinking/i.test(body);
}

// The sanitized body only goes upstream — Kimi keeps storing the bad blocks and
// replays them next turn, so without a memo every turn of a mixed-model session
// would burn one rejected round trip to rediscover the same thing. Keyed by
// session AND model: the very blocks that are foreign to one model are the
// legitimate signed history of the model that produced them.
const presanitizeMarks = new Map();

const presanitizeKey = (sessionKey, modelId) => (sessionKey ? `${sessionKey}\u0000${modelId}` : null);
const markPresanitize = (key) => { if (key) lruPut(presanitizeMarks, key, true); };
const needsPresanitize = (key) => !!key && lruTouch(presanitizeMarks, key) === true;

const toContentBlocks = (content) =>
  typeof content === 'string'
    ? [{ type: 'text', text: content }]
    : Array.isArray(content)
      ? content
      : [];

// Dropping an assistant turn can leave two user turns back to back, which the
// API rejects. Fold them into one, preserving block order (and with it the
// 1h-before-5m cache breakpoint ordering).
function mergeAdjacentUserMessages(messages) {
  const out = [];
  for (const message of messages) {
    const prev = out[out.length - 1];
    if (isRecord(prev) && prev.role === 'user' && isRecord(message) && message.role === 'user') {
      out[out.length - 1] = {
        ...prev,
        content: [...toContentBlocks(prev.content), ...toContentBlocks(message.content)],
      };
      continue;
    }
    out.push(message);
  }
  return out;
}

// Thinking signatures are bound to the model/provider that produced them.
// When Kimi switches models inside an existing session it can replay a foreign
// signed thinking block, which Anthropic rejects. Drop those blocks outright:
// the reasoning is scratch work whose conclusions already live in the adjacent
// text blocks. Keeping it as prefixed text instead would pay for it in tokens
// on every later turn AND show the model several of its own replies opening
// with that marker, which it then imitates. Normal same-model requests keep
// their signed blocks untouched.
function sanitizeHistoricalThinkingBody(body) {
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf-8'));
  } catch {
    return null;
  }
  if (!isRecord(parsed) || !Array.isArray(parsed.messages)) return null;

  let changed = false;
  const kept = [];
  for (const message of parsed.messages) {
    if (!isRecord(message) || message.role !== 'assistant' || !Array.isArray(message.content)) {
      kept.push(message);
      continue;
    }
    const content = message.content.filter((block) => {
      if (!isRecord(block) || (block.type !== 'thinking' && block.type !== 'redacted_thinking')) return true;
      changed = true;
      return false;
    });
    // An assistant turn that was nothing but thinking has nothing left to say.
    // Dropping it cannot orphan a tool_result: tool_use blocks always survive.
    if (content.length === 0) continue;
    kept.push({ ...message, content });
  }
  if (!changed) return null;

  const messages = mergeAdjacentUserMessages(kept);
  if (messages.length === 0) return null; // nothing left to send; let the error through
  parsed.messages = messages;

  // The request body changed, so reset and recompute its billing attestation.
  if (Array.isArray(parsed.system)) {
    for (const block of parsed.system) {
      if (!isRecord(block) || typeof block.text !== 'string') continue;
      if (!block.text.startsWith(BILLING_PREFIX)) continue;
      block.text = block.text.replace(/cch=[0-9a-f]{5}/i, CCH_PLACEHOLDER);
    }
  }
  const retryBody = Buffer.from(JSON.stringify(parsed), 'utf-8');
  if (retryBody.includes(CCH_PLACEHOLDER)) patchCch(retryBody);
  return retryBody;
}

// Ensure every assistant tool_use has a tool_result in the following user
// turn, synthesizing omissions and converting stale results to text.
function repairToolPairs(messages) {
  const allToolUseIds = new Set();
  for (const message of messages) {
    if (message.role !== 'assistant' || !Array.isArray(message.content)) continue;
    for (const block of message.content) {
      if (block.type === 'tool_use' && typeof block.id === 'string') allToolUseIds.add(block.id);
    }
  }

  const omittedResult = (toolUseId) => ({
    type: 'tool_result',
    tool_use_id: toolUseId,
    content: '[Tool result omitted during context management]',
    is_error: true,
  });

  const toStaleText = (block) => {
    const content = block.content;
    let text = '';
    if (typeof content === 'string') {
      text = content.trim().length > 0 ? content : '';
    } else if (Array.isArray(content)) {
      text = content
        .filter((e) => isRecord(e) && e.type === 'text' && typeof e.text === 'string')
        .map((e) => e.text)
        .join('\n');
    }
    if (text.length === 0) return null;
    return { type: 'text', text: `[stale tool result]\n${text}` };
  };

  const out = [];
  for (let index = 0; index < messages.length;) {
    const message = messages[index];
    const content = message.content;

    if (message.role === 'assistant' && Array.isArray(content)) {
      const seen = new Set();
      const toolUseIds = [];
      for (const block of content) {
        if (block.type === 'tool_use' && typeof block.id === 'string' && !seen.has(block.id)) {
          seen.add(block.id);
          toolUseIds.push(block.id);
        }
      }

      if (toolUseIds.length > 0) {
        out.push(message);
        const next = messages[index + 1];
        const nextContent =
          next && next.role === 'user' && Array.isArray(next.content) ? next.content : undefined;
        const usedIdx = new Set();
        const resultBlocks = toolUseIds.map((toolUseId) => {
          const matchedIndex = nextContent
            ? nextContent.findIndex(
                (block, i) =>
                  !usedIdx.has(i) && block.type === 'tool_result' && block.tool_use_id === toolUseId,
              )
            : -1;
          if (matchedIndex !== -1) {
            usedIdx.add(matchedIndex);
            return nextContent[matchedIndex];
          }
          return omittedResult(toolUseId);
        });

        if (nextContent) {
          const staleBlocks = [];
          const otherBlocks = [];
          for (let i = 0; i < nextContent.length; i++) {
            const block = nextContent[i];
            if (block.type !== 'tool_result') {
              otherBlocks.push(block);
              continue;
            }
            if (usedIdx.has(i)) continue;
            if (typeof block.tool_use_id === 'string' && allToolUseIds.has(block.tool_use_id)) continue;
            const stale = toStaleText(block);
            if (stale) staleBlocks.push(stale);
          }
          out.push({ ...next, content: [...resultBlocks, ...staleBlocks, ...otherBlocks] });
          index += 2;
        } else {
          out.push({ role: 'user', content: resultBlocks });
          index += 1;
        }
        continue;
      }
    }

    if (
      message.role === 'user' &&
      Array.isArray(content) &&
      content.some((b) => b.type === 'tool_result')
    ) {
      const kept = [];
      for (const block of content) {
        if (block.type !== 'tool_result') {
          kept.push(block);
          continue;
        }
        if (typeof block.tool_use_id === 'string' && allToolUseIds.has(block.tool_use_id)) continue;
        const stale = toStaleText(block);
        if (stale) kept.push(stale);
      }
      if (kept.length > 0) out.push({ ...message, content: kept });
      index += 1;
      continue;
    }

    out.push(message);
    index += 1;
  }
  return out;
}

const TRAILING_USER_PROMPT =
  'The previous turn produced no tool result. If you tried to call a tool, it was not recognized as a valid tool call (likely a formatting problem, or extra text emitted after the call). Re-issue the tool call on its own using the correct format. Otherwise, continue.';

// Prefill-restricted models reject conversations ending on an assistant turn.
function ensureTrailingUser(messages) {
  if (messages.length === 0) return messages;
  if (messages[messages.length - 1].role !== 'assistant') return messages;
  return [...messages, { role: 'user', content: [{ type: 'text', text: TRAILING_USER_PROMPT }] }];
}

// The full request-body pipeline. Order matters and mirrors the reference
// implementation's transformBody.
function transformBody(bodyStr) {
  let parsed;
  try {
    parsed = JSON.parse(bodyStr);
  } catch {
    return bodyStr;
  }
  if (!isRecord(parsed)) return bodyStr;

  try {
    if (typeof parsed.model === 'string') parsed.model = normalizeModelId(parsed.model);

    parsed.system = buildSystemLayout(parsed);

    // Strip effort for models that reject it (e.g. haiku).
    const override = getModelOverride(parsed.model || '');
    if (override && override.disableEffort) {
      if (isRecord(parsed.output_config)) {
        delete parsed.output_config.effort;
        if (Object.keys(parsed.output_config).length === 0) delete parsed.output_config;
      }
      if (isRecord(parsed.thinking) && 'effort' in parsed.thinking) {
        delete parsed.thinking.effort;
        if (Object.keys(parsed.thinking).length === 0) delete parsed.thinking;
      }
    }

    // NOTE: the reference prefixes tool names with mcp_ (Anthropic's billing
    // validation rejects lowercase tool names). Skipped for Kimi Code, whose
    // tool names are already PascalCase.

    if (typeof parsed.max_tokens === 'number') {
      parsed.max_tokens = Math.min(64000, parsed.max_tokens);
    }

    if (isThinkingEnabled(parsed.thinking) && parsed.context_management === undefined) {
      parsed.context_management = { edits: [{ type: 'clear_thinking_20251015', keep: 'all' }] };
    }

    injectMetadataUserId(parsed);

    if (shouldRelocateSystem()) applyLegacySystemRelocation(parsed);

    if (Array.isArray(parsed.messages)) {
      parsed.messages = repairToolPairs(parsed.messages);
      parsed.messages = ensureTrailingUser(parsed.messages);
    } else {
      parsed.messages = [];
    }

    applyCaching(parsed, getCacheControl());

    return JSON.stringify(parsed);
  } catch {
    return bodyStr;
  }
}

// ---------------------------------------------------------------------------
// Credentials: Keychain / file read, in-memory cache, refresh + write-back
// ---------------------------------------------------------------------------

const PRIMARY_SERVICE = 'Claude Code-credentials';
const CREDENTIALS_FILE = path.join(os.homedir(), '.claude', '.credentials.json');

function parseCredentials(raw) {
  let parsedJson;
  try {
    parsedJson = JSON.parse(raw);
  } catch {
    return null;
  }
  const data = parsedJson.claudeAiOauth || parsedJson;
  // Entries holding only mcpOAuth are MCP server credentials, not user accounts.
  if (parsedJson.mcpOAuth && !data.accessToken) return null;
  if (
    typeof data.accessToken !== 'string' ||
    typeof data.refreshToken !== 'string' ||
    typeof data.expiresAt !== 'number'
  ) {
    return null;
  }
  return {
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    expiresAt: data.expiresAt,
    subscriptionType: typeof data.subscriptionType === 'string' ? data.subscriptionType : undefined,
  };
}

function readKeychainService(serviceName) {
  try {
    return execFileSync('/usr/bin/security', ['find-generic-password', '-s', serviceName, '-w'], {
      timeout: 5000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch (err) {
    if (err && err.status === 44) return null; // item not found
    throw err;
  }
}

function listClaudeKeychainServices() {
  try {
    const dump = execSync('/usr/bin/security dump-keychain', {
      timeout: 5000,
      maxBuffer: 10 * 1024 * 1024,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const seen = new Set();
    const re = /"Claude Code-credentials(?:-[0-9a-f]+)?"/g;
    let m;
    while ((m = re.exec(dump)) !== null) seen.add(m[0].slice(1, -1));
    const ordered = [];
    if (seen.has(PRIMARY_SERVICE)) ordered.push(PRIMARY_SERVICE);
    for (const svc of seen) if (svc !== PRIMARY_SERVICE) ordered.push(svc);
    return ordered.length > 0 ? ordered : [PRIMARY_SERVICE];
  } catch {
    return [PRIMARY_SERVICE];
  }
}

function readCredentialsFile() {
  try {
    return parseCredentials(fs.readFileSync(CREDENTIALS_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

// Multiple accounts may exist (several Keychain entries). Keep it simple:
// KIMI_CLAUDE_AUTH_ACCOUNT picks a Keychain service name (or "file");
// otherwise the first account wins.
function readAllClaudeAccounts() {
  const rawAccounts = [];
  if (process.platform === 'darwin') {
    for (const svc of listClaudeKeychainServices()) {
      let raw = null;
      try {
        raw = readKeychainService(svc);
      } catch (err) {
        console.log(`kimi-claude-auth: warning: keychain read failed for "${svc}": ${err.message}`);
        continue;
      }
      if (!raw) continue;
      const creds = parseCredentials(raw);
      if (!creds) continue;
      rawAccounts.push({ source: svc, credentials: creds });
    }
  }
  if (rawAccounts.length === 0) {
    const creds = readCredentialsFile();
    if (creds) rawAccounts.push({ source: 'file', credentials: creds });
  }
  return rawAccounts;
}

function updateCredentialBlob(existingJson, newCreds) {
  let parsedJson;
  try {
    parsedJson = JSON.parse(existingJson);
  } catch {
    return null;
  }
  const target = parsedJson.claudeAiOauth || parsedJson;
  target.accessToken = newCreds.accessToken;
  target.refreshToken = newCreds.refreshToken;
  target.expiresAt = newCreds.expiresAt;
  return JSON.stringify(parsedJson);
}

function getKeychainAccountName(serviceName) {
  try {
    const output = execFileSync('/usr/bin/security', ['find-generic-password', '-s', serviceName], {
      timeout: 2000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const match = /"acct"<blob>="([^"]*)"/.exec(output);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

// Refresh tokens rotate on every refresh — the new credentials MUST be
// written back or the next refresh (by us or by Claude Code) fails.
function writeBackCredentials(source, creds) {
  const newCreds = {
    accessToken: creds.accessToken,
    refreshToken: creds.refreshToken,
    expiresAt: creds.expiresAt,
  };
  if (source === 'file') {
    try {
      const raw = fs.readFileSync(CREDENTIALS_FILE, 'utf-8');
      const updated = updateCredentialBlob(raw, newCreds);
      if (!updated) return false;
      fs.writeFileSync(CREDENTIALS_FILE, updated, { encoding: 'utf-8', mode: 0o600 });
      try { fs.chmodSync(CREDENTIALS_FILE, 0o600); } catch {}
      return true;
    } catch {
      return false;
    }
  }
  if (process.platform === 'darwin') {
    try {
      const raw = readKeychainService(source);
      if (!raw) return false;
      const updated = updateCredentialBlob(raw, newCreds);
      if (!updated) return false;
      // Claude CLI stores the macOS username as the account; using anything
      // else would create a duplicate entry instead of updating.
      const accountName = getKeychainAccountName(source) || source;
      execFileSync(
        '/usr/bin/security',
        ['add-generic-password', '-s', source, '-a', accountName, '-w', updated, '-U'],
        { timeout: 2000, stdio: 'ignore' },
      );
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function refreshAccountFromStorage(source) {
  if (source === 'file') return readCredentialsFile();
  try {
    const raw = readKeychainService(source);
    return raw ? parseCredentials(raw) : null;
  } catch {
    return null;
  }
}

// Direct OAuth refresh (zero LLM tokens consumed).
function refreshViaOAuth(refreshToken) {
  return new Promise((resolve) => {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: OAUTH_CLIENT_ID,
      refresh_token: refreshToken,
    }).toString();
    const req = https.request(
      OAUTH_TOKEN_URL,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(body),
        },
        timeout: 15000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
            if (!data.access_token) return resolve(null);
            resolve({
              accessToken: data.access_token,
              refreshToken: data.refresh_token || refreshToken,
              // Default 36000s (10h) matches observed Claude token lifetime.
              expiresAt: Date.now() + (data.expires_in || 36000) * 1000,
            });
          } catch {
            resolve(null);
          }
        });
      },
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end(body);
  });
}

// Fallback: ask the Claude CLI to refresh itself (consumes Haiku tokens).
function refreshViaCli() {
  for (let i = 0; i < 2; i++) {
    try {
      execSync('claude -p . --model haiku', {
        timeout: 60000,
        encoding: 'utf-8',
        env: { ...process.env, TERM: 'dumb' },
        stdio: 'ignore',
        cwd: os.tmpdir(),
      });
      return;
    } catch {
      // retry once, then give up
    }
  }
}

let accounts = [];
let activeSource = null;
const credentialCache = new Map(); // source -> { creds, cachedAt }
let refreshInFlight = null;

function getActiveAccount() {
  if (accounts.length === 0) return null;
  if (activeSource) {
    const found = accounts.find((a) => a.source === activeSource);
    if (found) return found;
  }
  return accounts[0];
}

async function refreshIfNeeded(account) {
  // Pick up external updates to the credentials file; Keychain state is only
  // mutated by our own write-back.
  if (account.source === 'file') {
    const onDisk = refreshAccountFromStorage(account.source);
    if (onDisk) account.credentials = onDisk;
  }

  const creds = account.credentials;
  if (creds.expiresAt > Date.now() + EXPIRY_MARGIN_MS) return creds;

  console.log(`kimi-claude-auth: token expiring for ${account.source}, refreshing via OAuth`);
  if (creds.refreshToken) {
    const oauthCreds = await refreshViaOAuth(creds.refreshToken);
    if (oauthCreds && oauthCreds.expiresAt > Date.now() + EXPIRY_MARGIN_MS) {
      account.credentials = oauthCreds;
      const wrote = writeBackCredentials(account.source, oauthCreds);
      console.log(`kimi-claude-auth: OAuth refresh ok, write-back ${wrote ? 'ok' : 'FAILED'}`);
      return oauthCreds;
    }
  }

  console.log('kimi-claude-auth: OAuth refresh failed, falling back to `claude` CLI');
  refreshViaCli();
  const refreshed = refreshAccountFromStorage(account.source);
  if (refreshed && refreshed.expiresAt > Date.now() + EXPIRY_MARGIN_MS) {
    account.credentials = refreshed;
    return refreshed;
  }
  return null;
}

async function getCredentials() {
  const account = getActiveAccount();
  if (!account) return null;

  const now = Date.now();
  const cached = credentialCache.get(account.source);
  if (
    cached &&
    now - cached.cachedAt < CREDENTIAL_CACHE_TTL_MS &&
    cached.creds.expiresAt > now + EXPIRY_MARGIN_MS
  ) {
    return cached.creds;
  }

  // Dedupe concurrent refreshes.
  if (!refreshInFlight) {
    refreshInFlight = refreshIfNeeded(account).finally(() => {
      refreshInFlight = null;
    });
  }
  const fresh = await refreshInFlight;
  if (!fresh) {
    credentialCache.delete(account.source);
    return null;
  }
  credentialCache.set(account.source, { creds: fresh, cachedAt: Date.now() });
  return fresh;
}

// ---------------------------------------------------------------------------
// Request headers: rebuilt from scratch — nothing client-supplied survives
// except anthropic-beta (merged) and the path.
// ---------------------------------------------------------------------------

function buildHeaders(accessToken, modelId, incomingBeta, excluded, contentLength, sessionId) {
  const betas = getModelBetas(modelId, excluded);
  for (const beta of String(incomingBeta || '').split(',').map((s) => s.trim()).filter(Boolean)) {
    if (!betas.includes(beta)) betas.push(beta);
  }

  return {
    authorization: `Bearer ${accessToken}`,
    accept: 'application/json',
    'accept-encoding': 'gzip, deflate, br, zstd',
    'anthropic-version': '2023-06-01',
    'anthropic-beta': betas.join(','),
    'anthropic-client-platform': 'desktop_app',
    'anthropic-client-version': CLIENT_VERSION,
    'anthropic-dangerous-direct-browser-access': 'true',
    'content-type': 'application/json',
    'content-length': contentLength,
    'x-app': 'cli',
    'user-agent': `claude-cli/${CC_VERSION} (external, local-agent, agent-sdk/${AGENT_SDK_VERSION})`,
    'x-client-request-id': crypto.randomUUID(),
    'x-claude-code-session-id': sessionId,
    'x-stainless-arch': process.arch === 'arm64' ? 'arm64' : process.arch,
    'x-stainless-lang': 'js',
    'x-stainless-os': process.platform === 'darwin' ? 'MacOS' : process.platform,
    'x-stainless-package-version': '0.94.0',
    'x-stainless-retry-count': '0',
    'x-stainless-runtime': 'node',
    'x-stainless-runtime-version': process.version,
    'x-stainless-timeout': '900',
  };
}

// Claude Code always calls /v1/messages with ?beta=true.
function buildUpstreamPath(requestUrl) {
  const url = new URL(requestUrl, 'http://localhost');
  if (url.pathname === '/v1/messages' && !url.searchParams.has('beta')) {
    url.searchParams.set('beta', 'true');
  }
  return url.pathname + url.search;
}

// ---------------------------------------------------------------------------
// Upstream plumbing
// ---------------------------------------------------------------------------

const agent = new https.Agent({ keepAlive: true });

function upstreamRequest(method, pathWithQuery, headers, bodyBuf) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname: UPSTREAM_HOST, port: 443, path: pathWithQuery, method, headers, agent },
      resolve,
    );
    req.on('error', reject);
    if (bodyBuf && bodyBuf.length > 0) req.write(bodyBuf);
    req.end();
  });
}

function readAll(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (c) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

function decompress(headers, buf) {
  const enc = String(headers['content-encoding'] || '').toLowerCase();
  try {
    if (enc === 'gzip') return zlib.gunzipSync(buf);
    if (enc === 'deflate') return zlib.inflateSync(buf);
    if (enc === 'br') return zlib.brotliDecompressSync(buf);
  } catch {
    // fall through: return raw
  }
  return buf;
}

// Headers safe to copy upstream->client. Hop-by-hop and framing headers are
// dropped; node re-chunks streamed responses itself.
function filterResponseHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (lk === 'content-length' || lk === 'transfer-encoding' || lk === 'connection') continue;
    out[k] = v;
  }
  return out;
}

function sendError(res, status, type, message) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ type: 'error', error: { type, message } }));
}

async function handleApiRequest(req, res, rawBody) {
  let modelId = 'unknown';
  let sessionKey = null;
  try {
    const incoming = JSON.parse(rawBody.toString('utf-8'));
    modelId = incoming.model || 'unknown';
    sessionKey = readUpstreamSessionKey(incoming); // read before transformBody rewrites it
  } catch {}
  const sessionId = sessionIdFor(sessionKey);
  const sanitizeKey = presanitizeKey(sessionKey, modelId);

  const creds = await getCredentials();
  if (!creds) {
    sendError(
      res,
      500,
      'authentication_error',
      'kimi-claude-auth: no valid Claude Code credentials. Run `claude` once to (re-)authenticate.',
    );
    return;
  }

  // Body pipeline: reshape -> serialize -> cch attestation signature.
  let outBody = rawBody;
  if (rawBody.length > 0 && (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
    outBody = Buffer.from(transformBody(rawBody.toString('utf-8')), 'utf-8');
    if (outBody.includes(CCH_PLACEHOLDER)) {
      const result = patchCch(outBody);
      if (result === 'unanchored') {
        console.log('kimi-claude-auth: warning: cch placeholder present but not patched; sending unattested request');
      }
    }
  }

  let didThinkingSignatureRetry = false;
  // This conversation already had a thinking signature rejected on this model,
  // and Kimi replays the same history every turn — sanitize up front instead of
  // spending another rejected round trip to be told the same thing.
  if (needsPresanitize(sanitizeKey)) {
    const presanitized = sanitizeHistoricalThinkingBody(outBody);
    if (presanitized) {
      outBody = presanitized;
      didThinkingSignatureRetry = true;
    }
  }

  const upstreamPath = buildUpstreamPath(req.url);
  const incomingBeta = req.headers['anthropic-beta'] || '';
  let token = creds.accessToken;
  const rebuildHeaders = () =>
    buildHeaders(token, modelId, incomingBeta, getExcludedBetas(modelId), outBody.length, sessionId);
  let headers = rebuildHeaders();

  let rateRetries = 0;
  let did401Retry = false;

  for (;;) {
    let up;
    try {
      up = await upstreamRequest(req.method, upstreamPath, headers, outBody);
    } catch (err) {
      sendError(res, 502, 'api_error', `kimi-claude-auth: upstream connect failed: ${err.message}`);
      return;
    }
    const status = up.statusCode || 502;

    // Success and non-retryable statuses stream back untouched (SSE-safe).
    const mayRetry = status === 400 || status === 401 || status === 429 || status === 529;
    if (!mayRetry) {
      res.writeHead(status, filterResponseHeaders(up.headers));
      up.pipe(res);
      up.on('error', () => res.destroy());
      return;
    }

    // Retryable statuses: buffer the (small) error body to decide.
    const rawErr = await readAll(up);
    const errText = decompress(up.headers, rawErr).toString('utf-8');

    if (!didThinkingSignatureRetry && isInvalidThinkingSignatureError(status, errText)) {
      const sanitized = sanitizeHistoricalThinkingBody(outBody);
      if (sanitized) {
        didThinkingSignatureRetry = true;
        markPresanitize(sanitizeKey);
        outBody = sanitized;
        headers = rebuildHeaders();
        console.log(`kimi-claude-auth: removed foreign thinking signatures for ${modelId}, retrying once`);
        continue;
      }
    }

    if ((status === 429 || status === 529) && rateRetries < 2) {
      const retryAfter = parseInt(up.headers['retry-after'], 10);
      const delay = Number.isNaN(retryAfter) ? (rateRetries + 1) * 2000 : retryAfter * 1000;
      // Beyond the cap the server is signalling a quota reset far in the
      // future — surface the error instead of hanging until then.
      if (delay <= getMaxRetryDelayMs()) {
        rateRetries++;
        console.log(`kimi-claude-auth: ${status} rate limited, retry ${rateRetries} in ${delay}ms`);
        await sleep(delay);
        continue;
      }
    }

    // 401: token expired mid-session — force a refresh and retry once.
    if (status === 401 && !did401Retry) {
      did401Retry = true;
      const account = getActiveAccount();
      if (account) credentialCache.delete(account.source);
      const fresh = await getCredentials();
      if (fresh && fresh.accessToken !== token) {
        token = fresh.accessToken;
        headers = rebuildHeaders();
        continue;
      }
    }

    // Long-context billing errors: drop one long-context beta and retry.
    if ((status === 400 || status === 429) && isLongContextError(errText)) {
      const beta = getNextBetaToExclude(modelId);
      if (beta) {
        addExcludedBeta(modelId, beta);
        console.log(`kimi-claude-auth: excluding beta ${beta} for ${modelId} after long-context error`);
        headers = rebuildHeaders();
        continue;
      }
    }

    // Give up: forward the decoded error body.
    const headersOut = filterResponseHeaders(up.headers);
    delete headersOut['content-encoding'];
    const errBuf = Buffer.from(errText, 'utf-8');
    headersOut['content-length'] = errBuf.length;
    res.writeHead(status, headersOut);
    res.end(errBuf);
    return;
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

function healthPayload() {
  const now = Date.now();
  const active = getActiveAccount();
  const describe = (a) => ({
    source: a.source,
    subscription: a.credentials.subscriptionType || null,
    expiresAt: new Date(a.credentials.expiresAt).toISOString(),
    valid: a.credentials.expiresAt > now + EXPIRY_MARGIN_MS,
  });
  return {
    // ok means "proxy process is up"; credential health is reported separately
    // so an expired token never looks like a dead proxy to the ensure-hook.
    ok: true,
    version: VERSION,
    uptime: Math.floor((now - START) / 1000),
    pid: process.pid,
    port: PORT,
    activeSource: active ? active.source : null,
    accounts: accounts.map(describe),
  };
}

const server = http.createServer((req, res) => {
  const t0 = Date.now();

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(healthPayload()));
    return;
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let model = '';
    try {
      model = JSON.parse(Buffer.concat(chunks).toString('utf-8')).model || '';
    } catch {}
    res.on('finish', () => {
      console.log(
        `[${new Date().toISOString()}] model=${model || '-'} path=${req.url} status=${res.statusCode} ms=${Date.now() - t0}`,
      );
    });
    handleApiRequest(req, res, Buffer.concat(chunks)).catch((err) => {
      sendError(res, 500, 'api_error', `kimi-claude-auth: internal error: ${err.message}`);
    });
  });
  req.on('error', () => res.destroy());
});

// Two sessions starting at once both probe the port, both find it dead and both
// spawn a proxy; the loser must lose quietly instead of dumping a stack trace
// into proxy.log. Any other listen error is a real failure.
server.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    console.log(`kimi-claude-auth: 127.0.0.1:${PORT} already has a proxy; this process exits`);
    process.exit(0);
  }
  console.error(`kimi-claude-auth: server error: ${err && err.message ? err.message : err}`);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`kimi-claude-auth v${VERSION} listening on http://${HOST}:${server.address().port} pid=${process.pid}`);

  accounts = readAllClaudeAccounts();
  if (accounts.length === 0) {
    console.log('kimi-claude-auth: WARNING: no Claude Code credentials found (Keychain or ~/.claude/.credentials.json)');
    return;
  }
  const wanted = process.env.KIMI_CLAUDE_AUTH_ACCOUNT;
  activeSource = (wanted && accounts.some((a) => a.source === wanted)) ? wanted : accounts[0].source;
  console.log(
    `kimi-claude-auth: accounts=[${accounts.map((a) => a.source).join(', ')}] active=${activeSource}`,
  );

  // Warm the cache / refresh up front so the first request is fast.
  getCredentials().then((creds) => {
    if (creds) {
      console.log(
        `kimi-claude-auth: credentials ready (token ${maskToken(creds.accessToken)}, expires ${new Date(creds.expiresAt).toISOString()})`,
      );
    } else {
      console.log('kimi-claude-auth: WARNING: credentials expired and could not be refreshed. Run `claude` to re-authenticate.');
    }
  });
});
