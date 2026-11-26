# mcp-session-journal

**Multi-session black-box journal, incremental summary files, and seamless handoff for MCP servers.**

> 用 AI 通过 MCP 操作设备/服务器时，做到一半突然没额度、来不及写交接文档，换新 AI 后完全不知道刚才干到哪了？  
> `mcp-session-journal` 为任意 MCP Streamable HTTP 服务提供**零外部依赖、多会话隔离、防突然断粮**的黑匣子录像与增量总结续接能力。

---

## 核心特性

- **黑匣子自动录像（防突然断额度）**：在 MCP 服务端自动记录每一次 `tools/call`（时间、工具名、参数、意图、耗时、退出码、输出头尾摘要、改动文件），旧 AI 瞬间断气也不丢现场。
- **每会话独立增量总结文件**：每个会话对应一份独立的 `summaries/<session_id>.md`，通过 `append_summary` 增量追加阶段总结；支持**第 1 次执行 + 每满 10 次未总结自动附轻提醒**（无损追加为 `content[1]`，不破坏原 `content[0]`，不依赖客户端是否支持 `instructions`）。
- **原生多会话隔离 + 单跳接力续写**：基于标准 `Mcp-Session-Id` 隔离并发任务；新 AI 调用 `resume(session_id, attach=true)` 接盘后，后续操作和总结自动续写到同一个会话与同一份 `.md` 文件里。
- **多进程安全 & 零第三方依赖**：纯 Python 标准库 + **SQLite WAL** 单事务存储，多个 MCP 进程共享同一份日志库也不会产生竞态。
- **内置脱敏与安全边界**：
  - 递归脱敏嵌套参数与敏感键名（`password` / `secret` / `token` / `api_key` / `sshpass` / `Bearer` / `sk-...` 等）；
  - 访问日志 URL 凭据打码（`/mcp/[REDACTED]`）；
  - `0700`/`0600` 权限、防符号链接打开（`O_NOFOLLOW`）、会话名严格校验、单文件与保留天数上限自动清理；
  - 命名空间化的可选元参数（`_journal_why` / `_journal_session`），绝不与上游工具已有参数冲突。

---

## 提供的 4 个 MCP 元工具

| 工具名 | 作用 |
|---|---|
| `list_sessions` | 列出最近活跃/未完结的会话（标题、目标、总步数、总结条数、最后命令与成败状态） |
| `resume` | 一键拉取指定（或最近）会话的增量总结 `.md`、任务便签、改动文件及最近操作流水；默认 `attach=true` 绑定当前连接继续录像 |
| `append_summary` | 向当前会话的独立 Markdown 文件增量追加 2~4 行阶段小总结（附可选 `next_step`） |
| `task_note` | 更新会话结构化便签（`title` / `goal` / `done` / `blockers` / `next` / `notes` / `status`） |

---

## 快速开始

### 方式 1：直接嵌入你自己的 Python MCP Server

参考 [examples/http_mcp_server.py](examples/http_mcp_server.py)：

```bash
MCP_TOKEN="your-secret-token" python3 examples/http_mcp_server.py
```

### 方式 2：零侵入套在任意现有 HTTP MCP Server 前面（透明代理）

参考 [examples/http_mcp_proxy.py](examples/http_mcp_proxy.py)：

```bash
UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=8766 \
MCP_PORT=8765 MCP_TOKEN="your-secret-token" \
python3 examples/http_mcp_proxy.py
```

代理会自动：
1. 在 `initialize` 响应中追加协作说明；
2. 在 `tools/list` 中注入上述 4 个元工具及 `_journal_why` / `_journal_session` 可选参数；
3. 转发 `tools/call` 前剥离命名空间元参数，并在返回后自动写入黑匣子、按第 1 次 / 每 10 次规则附轻提醒。

---

## 无状态客户端的会话粘连（sticky sessions）

很多客户端（如每次调用都新建连接、不回传 `Mcp-Session-Id` 的代理）会让每次调用都变成一个一步会话。journal 按**客户端指纹**把它们续接起来：

- 指纹优先取**客户端标签**：`/mcp/<token>/<label>`、`X-MCP-Client: <label>` 或 `?client=<label>`（`[A-Za-z0-9._-]{1,40}`，不区分大小写，同一个库内全局共享）。标签非法、重复或互相冲突时直接拒绝请求，不会悄悄退回。没有标签时用 IP + User-Agent；转发 IP 头只在 TCP 对端是回环地址（本地隧道）时才采信。
- 同指纹的新连接在空闲窗口内（`MCP_JOURNAL_STICKY_SECONDS`，默认 7200）续接该指纹上次使用的活跃会话；不带会话头但有指纹的调用各自开新会话，不再共用 `default`。
- 解析、建行、写链接在同一个 `BEGIN IMMEDIATE` 事务里完成，并发首调和多进程共享库都不会分裂或写出矛盾绑定。
- `resume` 绑定当前连接与指纹；`resume session_id=new` 总是新建会话；`task_note status=done` 会解除指向该会话的所有绑定和粘连，旧连接之后自动换到新会话。
- 显式 `session_id` / `_journal_session` 只作用于本次调用，不改粘连；普通调用也不会把客户端已切走的粘连拉回旧会话。
- 同一标签下并行跑多个任务会合并，请为每个任务用 `_journal_session` 或不同标签。
- `list_sessions` 默认隐藏一步、无标题、无交接内容的会话（`include_trivial=true` 显示）。
- 访问日志只记录方法、路由类别和状态码，不记录路径和查询串。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MCP_JOURNAL_DIR` | `~/.local/state/mcp-sessions` | SQLite 库与 `summaries/*.md` 存储根目录 |
| `MCP_JOURNAL_RETENTION_DAYS` | `14` | 自动清理超过 N 天未更新的旧会话 |
| `MCP_JOURNAL_MAX_EVENTS` | `500` | 单会话保留的最大黑匣子事件条数 |
| `MCP_JOURNAL_MAX_SESSIONS` | `200` | 最多保留的会话总数 |
| `MCP_JOURNAL_STICKY_SECONDS` | `7200` | 同客户端指纹续接会话的空闲窗口（秒），`0` 关闭粘连 |

---

## 换新 AI 接盘时的用法

当上一个 AI 突然没额度中断后，打开新 AI 连上同一个 MCP，直接发一句：

> 上个 AI 断额度了，先调 `list_sessions` 找到刚才的任务，然后 `resume` 看一下进度和总结，接着做。

---

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT

