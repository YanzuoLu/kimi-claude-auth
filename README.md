# kimi-claude-auth

让 Kimi Code CLI 复用本机 Claude Code 已登录的 OAuth 订阅凭证访问 Anthropic API（claude 系列模型）——**不需要 API key，不需要重新 OAuth 登录**。

实现方式：一个只监听 `127.0.0.1` 的本地 HTTP 代理（零 npm 依赖，仅用 Node 内置模块），把 Kimi Code 发出的 Anthropic 请求"整形"成与官方 Claude Code 一致的形态后转发到 `api.anthropic.com`。请求整形逻辑移植自 [opencode-claude-auth](https://github.com/griffinmartin/opencode-claude-auth)（MIT 协议）的 fetch 拦截器。

## English Quickstart

Use Claude models in [Kimi Code CLI](https://www.kimi.com/code/) with your local Claude Code OAuth credentials — no API key, no second login. A zero-dependency Node proxy on `127.0.0.1:8320` reads your Claude Code OAuth token (macOS Keychain or `~/.claude/.credentials.json`), reshapes requests into the official Claude Code wire format (billing header, beta flags, identity, prompt caching), and forwards them to `api.anthropic.com`.

1. Prereqs: Claude Code installed and signed in once (`claude`), Node 18+, Kimi Code CLI.
2. Install the plugin in Kimi Code: `/plugins install https://github.com/YanzuoLu/kimi-claude-auth` (or a local path), then `/reload`.
3. Add to `~/.kimi-code/config.toml`:

   ```toml
   [providers.claude]
   type = "anthropic"
   base_url = "http://127.0.0.1:8320"
   api_key = "oauth-via-proxy"   # placeholder; the proxy replaces it

   [models."claude-sonnet-4-6"]
   provider = "claude"
   model = "claude-sonnet-4-6"
   max_context_size = 200000
   ```

4. `/model` → pick `claude-sonnet-4-6`. The SessionStart hook auto-starts the proxy.

Disclaimer: this reuses subscription OAuth tokens with a third-party client and may violate Anthropic's Terms of Service; use at your own risk. 中文文档见下文。

## 前置条件

- macOS（凭证读取依赖 Keychain；Linux 上回退读 `~/.claude/.credentials.json`）
- 已安装并**登录过** Claude Code（`claude` 跑通过一次，Keychain 里存在 `Claude Code-credentials` 条目）
- Node.js 18+（`node` 在 PATH 中）
- Kimi Code CLI

## 安装

```bash
# 在 Kimi Code CLI 中：
/plugins install /Users/ol125/Documents/kimi-claude-auth
```

插件用两个 hook 保证代理可用（都跑同一个 `hooks/proxy-ensure.cjs`，日志写到插件目录下 `proxy/proxy.log`）：

- `SessionStart`：会话开始时探测 `/health`，没在跑就守护化拉起，并打印一行状态
- `UserPromptSubmit`：每次发消息前复查，**正常情况下完全静默**（这条路径的 stdout 会被追加进上下文），只有代理起不来时才出声；10 秒内已确认过健康就跳过探测（时间戳记在 `proxy/.health-stamp`）

两个 hook 都会把 `/health` 返回的 `version` 与 `kimi.plugin.json` 比对。代理是 detached 进程，不随会话退出，所以升级插件后旧进程会一直跑旧代码——版本对不上时按 `/health` 里的 `pid` kill 掉，等端口释放后用新代码重新拉起（代理设了 `process.title`，`pkill -f` 在 macOS 上匹配不到，只能用 pid）。

## 配置 Kimi Code

在 `~/.kimi-code/config.toml` 中添加（hook 检测到缺失时也会在会话开头提示）：

```toml
[providers.claude]
type = "anthropic"
base_url = "http://127.0.0.1:8320"
api_key = "oauth-via-proxy"   # 占位，代理会覆写

[models."claude-sonnet-4-6"]
provider = "claude"
model = "claude-sonnet-4-6"
max_context_size = 200000
```

`api_key` 随便填——代理会丢弃客户端的 `x-api-key` / `authorization`，换成 Keychain 里的 OAuth Bearer token。之后在 Kimi Code 里选用 `claude-sonnet-4-6`（或自行添加 `claude-opus-4-7`、`claude-haiku-4-5` 等模型条目）即可。

## 原理

### 凭证

- 启动时从 macOS Keychain 读取 `Claude Code-credentials*` 条目（可能有多个，默认用第一个，`KIMI_CLAUDE_AUTH_ACCOUNT` 可指定服务名）；找不到则回退 `~/.claude/.credentials.json`
- 内存缓存 30s TTL
- token 临期（60s 内）时直接 `POST https://claude.ai/v1/oauth/token` 刷新，并把新凭证**回写** Keychain / 文件（refresh token 每次轮换，不回写会导致下次刷新失败）；直接刷新失败时回退到调用 `claude` CLI 让它自己刷新
- 日志只输出 token 的掩码形式，绝不打印完整 token

### 请求整形流水线（对 `POST /v1/messages` 的 body，按序执行）

1. `model` 归一化（去掉 `[1m]` / `-1m` 后缀，1M context 仅靠显式后缀或 `ANTHROPIC_ENABLE_1M_CONTEXT=true` 开启）
2. system 重排为 Claude Code 标准布局：`[计费头, Claude 身份, ...其余]`，其中计费头为 `x-anthropic-billing-header: cc_version=<ver>.<sha256抽样3位>; cc_entrypoint=local-agent; cch=00000;`
3. 对不支持 effort 的模型（haiku）剥掉 `output_config.effort` / `thinking.effort`
4. `max_tokens` 钳制到 64000
5. 开启 thinking 且未显式设置时，注入默认 `context_management`（`clear_thinking_20251015`）
6. `metadata.user_id` 稳定化为包含 `session_id` 的 JSON：每个上游 Kimi 会话映射到一个独立且稳定的 UUID（key 取请求里原始 `metadata.user_id` 的 `session_id`，最多记 64 个会话，取不到时回退到进程级 UUID）。一个代理进程会服务多个 Kimi 会话，全部塞同一个 session_id 在 Anthropic 看来就是一个 Claude Code 客户端在并发发请求
7. 第三方 system prompt（如 Kimi Code 自己的身份）默认挪进第一条 user message（`KIMI_CLAUDE_AUTH_KEEP_SYSTEM=1` 可关闭）——这是 Claude Code 计费识别的关键行为
8. 修复 tool_use/tool_result 配对（缺失的补占位 result、孤儿 result 转文本）；会话末尾是 assistant 消息时补一条 user 消息（带 prefill 限制的模型要求）
9. prompt caching：已有的 5m ephemeral breakpoint 升级为 OAuth 默认 1h TTL，按 Claude Code 布局在 system 末尾与最近消息上放置 breakpoint，强制执行 Anthropic 4 个 breakpoint 上限，并保证 1h breakpoint 排在 5m 之前
10. 序列化后做 **cch 签名**：用纯 JS 实现的 xxHash64（固定 seed）对整个 body 求 hash，取低 20 bit 的 5 位十六进制替换计费头里的 `cch=00000` 占位符

与参考实现的一处刻意差异：跳过 tool 名的 `mcp_` 前缀转换（Kimi Code 的工具名本身已是 PascalCase，响应方向因此可以逐字节透传）。

### 请求头重建

客户端头全部丢弃（包括 `x-api-key`、`authorization`、`user-agent`），仅保留路径与合并后的 `anthropic-beta`，重建为 Claude Code 指纹：

- `authorization: Bearer <OAuth token>`、`anthropic-version: 2023-06-01`
- `anthropic-beta`：默认集合（`claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advanced-tool-use-2025-11-20`）+ 末尾 `extended-cache-ttl-2025-04-11`，并按模型增删（haiku 去掉 interleaved-thinking；4-6/4-7 加 effort beta；`-1m` 模型加 context-1m beta）
- `user-agent: claude-cli/<ver> (external, local-agent, agent-sdk/<ver>)`、`x-app: cli`、`anthropic-client-platform/version`、`anthropic-dangerous-direct-browser-access`
- 一组 `x-stainless-*` 头、`x-client-request-id`（每请求随机）、`X-Claude-Code-Session-Id`（与 body 里的 `session_id` 同源，按上游会话稳定）
- `/v1/messages` 自动补 `?beta=true`

响应方向不做任何变换，SSE 逐块流式透传，成功路径不缓冲。

### 重试

- 429/529：尊重 `retry-after` 最多重试 2 次，等待超过 `KIMI_CLAUDE_AUTH_MAX_RETRY_MS`（默认 30s）就直接把错误透传给客户端（那通常意味着小时级的配额重置，重等没意义）
- 401：强制刷新凭证后重试一次
- 长上下文计费错误（400/429 且错误文本匹配）：逐个剔除长上下文 beta flag 重试（进程内记忆）
- 400 且报 thinking 签名无效：thinking 签名绑定在生成它的模型上，会话中途换模型时 Kimi 会把旧模型签名的 thinking 块重放上去。这时把历史里所有 `thinking` / `redacted_thinking` 块**直接丢弃**后重试一次——思考过程丢掉即可，结论本来就在 assistant 的 text 块里；转成带前缀的普通文本会永久占 token，而且模型看到自己前几轮回复都带这个前缀，会跟着模仿。清完为空的 assistant 消息整条删掉，必要时合并相邻的 user 消息（tool_use 块不会被删，配对不受影响）
- 清洗后的 body 只发给上游，Kimi 本地存的历史仍然带着坏签名块，下一轮还会原样重放。所以同一「会话 + 模型」命中过一次后就记住（最多 64 条），后续请求直接预清洗，不再每轮先撞一次 400

## 环境变量

| 变量 | 说明 | 默认 |
|---|---|---|
| `KIMI_CLAUDE_AUTH_PORT` | 代理监听端口 | `8320` |
| `KIMI_CLAUDE_AUTH_ACCOUNT` | 指定 Keychain 服务名（或 `file`）选择账号 | 第一个账号 |
| `KIMI_CLAUDE_AUTH_MAX_RETRY_MS` | 429/529 重试等待上限（毫秒） | `30000` |
| `KIMI_CLAUDE_AUTH_CACHE_TTL` | 设为 `5m`/`none`/`off` 关闭 1 小时缓存 TTL | OAuth 默认 `1h` |
| `KIMI_CLAUDE_AUTH_KEEP_SYSTEM` | 设为 `1` 时保留第三方 system prompt 不迁移 | 关闭（默认迁移） |
| `KIMI_CLAUDE_AUTH_RELOCATE_SYSTEM` | 遗留开关，设为 `0`/`false`/`off` 关闭迁移 | 开启 |
| `ANTHROPIC_BETA_FLAGS` | 覆盖默认 beta flag 集合（逗号分隔） | 见上文默认集合 |
| `ANTHROPIC_ENABLE_1M_CONTEXT` | 设为 `true` 时对 Sonnet/Opus 4.6 全局开启 1M context beta | `false` |

环境变量需要在代理进程的环境里设置（比如写进 shell profile，或手动启动代理时带上）。

## 故障排查

| 症状 | 可能原因 | 处理 |
|---|---|---|
| hook 提示 proxy 起不来 | 端口被占用 / Node 太旧 | 看 `proxy/proxy.log`；`lsof -i :8320` 查占用；或用 `KIMI_CLAUDE_AUTH_PORT` 换端口（config.toml 同步改） |
| `/health` 里 `accounts` 为空 | 没登录过 Claude Code | 跑一次 `claude` 登录 |
| 请求 401 | token 过期且刷新失败 | 手动跑 `claude` 重新登录；看 proxy.log 里 refresh 相关行 |
| 请求 401 且 Keychain 弹窗被拒绝 | 终端/Node 无 Keychain 权限 | 弹窗里选"始终允许"；或删除条目后用 `claude` 重新登录 |
| 请求 400 提到 beta | 模型不支持某个 beta flag | 用 `ANTHROPIC_BETA_FLAGS` 裁剪后重启代理 |
| 长上下文报 extra usage | 订阅不含 1M context 计费 | 别用 `-1m` 后缀模型；代理也会自动剔除 context-1m beta 重试 |
| 想确认代理整形后的样子 | — | `curl -s http://127.0.0.1:8320/health` 看凭证状态；请求日志每请求一行在 `proxy/proxy.log` |
| Kimi Code 没走代理 | config.toml 里 provider 没配对 | 确认 `[providers.claude]` 的 `base_url` 与端口一致，且模型的 `provider = "claude"` |
| `proxy.log` 里出现 `already has a proxy; this process exits` | 两个会话同时探测到端口没人应答，抢着拉代理 | 正常现象，后启动的那个会静默退出，不影响先起来的那个 |
| 升级插件后行为没变化 | 旧代理进程还在跑旧代码 | hook 会自动按版本替换；也可 `curl -s http://127.0.0.1:8320/health` 看 `version` 是否等于 `kimi.plugin.json` 里的版本 |

手动运行代理（调试用）：

```bash
node /Users/ol125/Documents/kimi-claude-auth/proxy/proxy.js
# 另开一个终端：
curl -s http://127.0.0.1:8320/health | python3 -m json.tool
curl -s http://127.0.0.1:8320/v1/messages -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
```

## 免责声明

本插件通过复用本机 Claude Code 的 OAuth 凭证，让第三方客户端（Kimi Code）以 Claude Code 的请求形态访问 Anthropic API。这属于对订阅服务访问方式的非官方利用，**可能违反 Anthropic 的服务条款**；Anthropic 可能随时调整风控策略导致本插件失效，极端情况下可能影响你的账号。请自行评估风险后使用，仅限个人学习与研究用途。本项目与 Anthropic、Moonshot AI 无任何官方关联。

请求整形思路与行为规格来自 MIT 协议的开源项目 opencode-claude-auth（griffinmartin 及其 fork 作者），在此致谢。
