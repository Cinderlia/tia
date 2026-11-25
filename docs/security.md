# 安全边界：工具输入是数据，不是命令

TIA 自己在做安全测试，所以更不能让"被测输入"或"模型输出"变成我们自己的执行面。
下面每一条都是代码里的硬约束，不是建议。

## 1. 不执行任何字符串

- 没有 `subprocess`、`os.system`、`eval`、`exec`、`compile`。
- 唯一的动态导入是 `cap/registry.py` 里**写死**的 `handler_path` 白名单；
  工具名来自 profile 白名单，未注册/未下发一律 `NOT_FOUND`（主 agent 的 22 个工具直接不注册）。
- 模型（planner）只能"选工具名 + 填 JSON 参数"，参数经 pydantic `extra="forbid"` 校验；
  模型给出的任何字符串都不会被当作代码或命令执行。

## 2. 文件路径

- `ad/fs.py` 的所有读写先 `Path.resolve()`，必须 `is_relative_to(app_root)`，否则 `POLICY_DENIED`（H1）。
- `artifact_save` 只写 `impl/var/artifacts/<case_id>/`，文件名白名单 `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`，
  拒绝 `..`、绝对路径、含空格与分号的名字；写前再次 `is_relative_to` 校验。
- 产物内容上限 1 MiB，超限 `BAD_ARGS`。

## 3. SQL

- 只经 `cap/sqlparse.py`：
  - 读：仅 `SELECT / SHOW / EXPLAIN / DESCRIBE`；
  - 写：仅单条 `INSERT / UPDATE / DELETE`，`UPDATE/DELETE` 必须带 `WHERE`；
  - 统一拒绝：多语句、注释、DDL、`information_schema/mysql` 等系统库、`INTO OUTFILE`。
- 写还必须过 `cap/policy.check_write`：case 存在、表在 `profile.write_allow_tables ∪ case.write_targets`、
  列未被 deny、行数 ≤ `max_rows_per_write`；每次写都落 `change` 并带 `undo_sql`（H3/H4）。

## 4. HTTP

- 只接受绝对 `http(s)` URL；`follow_redirects=False` 并逐跳记录 `redirect_chain`（H2）。
- 不注入 Cookie、不伪造会话；登录只能由人通过 `session_bind` / `human_ask` 提供。
- 响应体按 `max_http_bytes` 截断并返回 `TRUNCATED` 警告，不静默丢数据。

## 5. 资源与预算

- 工具参数全部有上界（行数、字节数、条目数、超时）；超出直接 `BAD_ARGS`。
- `Kernel` 按 profile 计数，超预算 `BUDGET_EXCEEDED`（H12）；`main` 的 22 个工具从未注册（H11）。
- 所有工具调用返回统一信封，异常收敛为 `ENV_ERROR`，不把堆栈抛给模型。

## 6. 模型输出永远不是结论

`verify_tag` 只返回事实（命中位置、上下文、`verdict_ceiling`）；verdict 由各 agent 的 judge 规则计算。
报告里的安全结论必须能指回 `ev://` 证据，模型没有"直接写结论"的通道。
