# TIA

**Trace-based Injection Agent** —— 用「合法请求 + 数据库观测 + 探针」证明：某个 sink 被真实到达，某个值是被应用自己写进库的。

TIA 不做 payload 生成器，也不做漏洞扫描器。它把「漏洞存在」这个结论拆成两类可证伪的命题：

1. **触发（trigger）**：从某个读点出发，应用自己把库里的值读出来并执行了；
2. **注入（inject）**：外部用户从一条合法入口出发，应用自己把这个值写进了库，并且读路径能把它读回来。

对这两类命题，TIA 只交付**证据链**与**可归因的 verdict**，不伪造会话、不改目标应用源码、不直接写目标列。

---

## 仓库状态

当前处于**骨架搭建阶段**：仓库初始化完成，实现代码（`impl/`）尚未落地。
设计与任务拆解在本地 `tia-design-kit/` 中（该目录不纳入版本库，见 `.gitignore`），实现以其中的《模块化设计》《工具接口文档》《验收判定规范》为准。

## 目录结构

```text
.
├── .gitignore          # 忽略设计资料、工作区与各类构建产物
├── README.md
├── docs/
│   └── environment.md  # 开发/测试环境事实与依赖安装规约
├── impl/               # 实现（规划中）
│   ├── pyproject.toml
│   ├── src/tia/        # server / orch / dom / cap / ad / inf
│   ├── profiles/       # main / trigger / inject 三份 profile
│   ├── probe-php/      # PHP 写点/读点采集器
│   ├── tests/          # unit / contract / e2e / fixtures
│   └── scripts/
├── tia-design-kit/     # 设计资料（本地，不提交）
└── dsh-workdir/        # 开发工作区（本地，不提交）
```

## 架构总览

三个编排进程 + 一个共享能力服务：

```text
tia-agent main     调度队列，切分切片，转发交付物，不做验证
      │
      ├── tia-agent trigger   读点 → sink：证明“应用会执行这个值”
      └── tia-agent inject    合法入口 → 写点：证明“用户能把这个值写进来”
                    │
                    └── tia-server（MCP stdio，36 个工具，按 profile 授权）
                              ├── cap.*  能力层：源码 / 库 / 探针 / HTTP / 验收
                              ├── ad.*   适配层：fs / mysql / php_probe / http / browser
                              └── inf.*  基础设施：store / log / config
```

- **主 Agent** 只做调度：读队列 → 选片 → 生成 `SliceBrief` → 分派 → 转发 `TriggerHandoff` → 归档。它不持有验证类与写类工具（不注册即不可用）。
- **触发 Agent** 走 P0–P6：定位读点与入口 → 挂探针 → 备数据 → 写 payload → `verify_tag` → 回滚 + 报告。
- **注入 Agent** 走 I0–I7：断言基线 → 重建入口 → 标定变换 → 求交选点 → 投递 → 三态验收 → 收尾。
- **共享服务** `tia-server` 是一份实现、三种 profile：同一套 `verify_tag` 与探针语义保证两个 agent 的结论可比。

三段跨 agent 契约：`SliceBrief`（主 → 触发）、`TriggerHandoff`（触发 → 主 → 注入）、`CaseOutcome`（触发/注入 → 主）。

## 核心原则

| 约束 | 含义 |
|---|---|
| **H1 只读目标源码** | 写只落在数据库与本项目目录 |
| **H2 不伪造会话** | 登录走 `session_bind` + `human_ask`，不注入 Cookie、不改源码绕鉴权 |
| **H3 目标列只经应用写入** | 前置数据可直写，但必须带 undo 进 Journal |
| **H4 写库必可回滚** | 每次写返回 `change_id` + `undo_sql`，回滚后 `residue == 0` |
| **H5 验收只回事实** | `verify_tag` 返回 `occurrences` 与 `verdict_ceiling`，不下结论 |
| **H6 禁止全量 trace** | `trace_run` 必须带 filter，否则 `BAD_ARGS` |
| **H9 错误不抛异常** | 统一 `{ok:false, error:{code, message, retryable, hint}}`，错误码闭集 |
| **H10 证据带时间与版本** | 副作用记录 `observed_at` 与源码 `sha256` |
| **H11 主 Agent 不见验证工具** | 四道闸（不注册 / 配额 / 构造期定 profile / 静态断言）保证 |

`verify_tag` 的 verdict 上限是 `EXECUTABLE`（结构上会执行），不写 `EXECUTED`——除非有带外探针。

## 技术栈

Python 3.11+ · uv · 官方 `mcp` SDK（stdio）· pydantic v2 ·
`pydantic-graph` + `pydantic-ai`（仅 planner）· httpx · selectolax/lxml ·
PyMySQL / sqlite3 · structlog JSONL · pytest + pytest-asyncio · ruff + mypy strict。
PHP 8 采集器单独放在 `impl/probe-php/`。

## 快速开始（骨架落地后）

```bash
cd impl
uv sync
uv run pytest -q
uv run ruff check src && uv run mypy src

# 起共享能力服务（stdio）
uv run tia-server --profile trigger

# 跑一个 case
uv run tia-agent trigger --case c001
uv run tia-agent inject --case c001
uv run tia-report c001
```

三个 profile 的授权范围不同：`main` 只有 14 个只读/调度工具；`trigger` 与 `inject` 按需开放写与验证能力，写域由 profile 的 `write_allow_tables` / `write_deny_columns` 收口。

## 开发与测试环境

- **开发机 / 仓库**：`jmliang@172.28.8.69:/home/jmliang/tia`，远程 `git@github.com:Cinderlia/tia.git`。
- **测试容器**：`docker exec -it --user root -w /app php84-dev bash`。容器为 Debian 13 + PHP 8.4.25 + Apache + MariaDB；`/home/jmliang/tia` 挂载到 `/home/so/tia`；端口 `8008→80`、`3006→3306`；目标应用（bWAPP / DVWA / WeGIA 等）位于 `/app`。
- **本地模型**：OpenAI 兼容，`http://172.28.8.100:8000/v1`，模型 `Qwen3.8-27B`，Key `sk-a-strong-key`；不计量，供 planner / judge 使用。
- **依赖规约**：Python 包与 apt 包一律装在容器内，并同步登记到 `impl/pyproject.toml` / `impl/requirements-extra.txt` / `impl/deploy/apt-packages.txt`，换环境可一键还原。

完整事实与变更记录见 [`docs/environment.md`](docs/environment.md)。

## 里程碑

| 阶段 | 内容 | 验收 |
|---|---|---|
| **M0** | 工程骨架：三个入口能启动、36 工具可列出、信封与错误码契约、写闸门 | `tia-server` 起得来，`POLICY_DENIED` 生效 |
| **M1** | 只读闭环：源码 / 入口 / 库只读 / `verify_tag` | 给 sink 与成功流程，能复述“填哪些字段、点几次” |
| **M2** | 数据与写：探针、标定、投递、undo | bWAPP `xss_stored_1.php` 跑到 `EXECUTABLE`，回滚后 `residue == 0` |
| **M3** | 归因交付：trace / guard / 三态归因 | 失败能落到四类归因并给出回退目标 |
| **M4** | 调度闭环：队列、预算、熔断、报告 | 多切片自动跑完并出 Markdown 报告 |

## 不在范围内

Web UI、模型微调、payload 生成器、IDA/Burp 集成、对目标应用的任何源码修改。

## 开发约定

- 类型即文档：pydantic 模型，禁止 `**kwargs` 与裸 `dict` 穿透模块边界。
- 信封由 registry 统一包装，handler 只返回 `data` 或抛 `ToolError`。
- 依赖方向单向：`orch → cap.registry → handler → core + adapter`；adapter 不含业务判断，cap 不写 SQL 业务。
- 每个任务完成后在 `tia-design-kit/TASKS.md` 勾选，偏差写 `NOTES.md`。
- 提交前：`ruff` + `mypy` 零错误，单测与契约测试全绿。

---

设计口径以 `tia-design-kit/` 为准；实现与文档不一致时，先改文档再改代码，或把偏差明确记入 `NOTES.md`。
