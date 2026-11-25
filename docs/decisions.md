# 实现决策与设计偏差

> 格式沿用设计包 `NOTES.md`：每条记「文档 / 实现 / 原因 / 需回写文档」。
> 设计包本身（`tia-design-kit/`）不纳入版本控制，偏差统一记在这里；
> 冲突时以《工具接口文档》《验收判定规范》为准。

## D1 `verify_tag` 增加可选输入 `payload` / `content_type` / `headers` / `status`

- 文档：《验收判定规范》§5.4 输入只有 `url|html / params / session_id / tag / max_occurrences / upwalk`。
- 实现：`VerifyTagInput` 额外接受 `payload`（完整注入内容）、以及离线模式下的响应元信息
  `content_type` / `headers` / `status`。
- 原因：
  1. Q1 闭合、Q2 承载需要看**注入内容**，只有 4 字符 tag 时无法判断，只能给保守 false；
  2. 离线模式要与在线模式结果一致（§9），但离线调用方必须能提供 `text/plain`、CSP、4xx
     这些在线响应才有的信号。
- 兼容性：全部可选，不传时行为与文档一致（保守解）。
- 需回写文档：是（§5.4 输入表补 4 个可选字段）。

## D2 `JsonValue` 不使用递归类型别名

- 文档：《模块化设计》要求"类型即文档"，信封 `data` 为 JSON 值。
- 实现：`data: dict[str, Any] | list[Any] | str | int | float | bool | None`。
- 原因：pydantic 2.14 对隐式递归别名建 schema 时 `RecursionError`；PEP 695 的 `type`
  语法要求 Python 3.12+，而项目下限是 3.11。深层结构由各工具的 pydantic 模型约束。
- 需回写文档：否（属实现细节）。

## D3 在线 `verify_tag` 不跟随重定向

- 文档：H2 要求 httpx 显式 Cookie、`follow_redirects=False`；`verify_tag` 未特别说明。
- 实现：3xx 时照常判定响应体，并返回 `warnings: ["REDIRECT_NOT_FOLLOWED: <location>"]`。
- 原因：静默跟随会掩盖"入口实际跳到了登录页"这类关键事实；让 agent 显式决定下一步。
- 需回写文档：是（§5.4 行为说明补一条）。

## D4 `session_id` 暂未接入

- 文档：`verify_tag` 接受 `session_id`，用绑定会话取页面。
- 实现：接受参数但返回 `warnings: ["SESSION_NOT_IMPLEMENTED: ..."]`；会话存储随
  `cap/session.py` + `session_bind`（M2）落地后接入。
- 需回写文档：否（阶段性）。

## D5 URL 只接受绝对 http(s)

- 文档：示例给的是相对路径 `/html/...`，依赖环境 base_url。
- 实现：当前要求绝对地址，否则 `BAD_ARGS`；base_url 配置随 `inf/config.py` 引入。
- 需回写文档：是（§5.4 输入说明）。

## D6 上下文判定的实现取舍

- `title` 按 §3.3 归 `html_text` 且 `TITLE_NOT_EXECUTABLE`；`pre` 归 `plain_text`（§5 表格）。
- `<style>` 归 `attr` + `STYLE_NOT_SCRIPTABLE`（8 类里没有 style 专属类）。
- JS 行/块注释里的命中归 `script_block` + `JS_COMMENT`（不可执行）。
- 需回写文档：是（§5 判定表补 style / JS 注释两行）。

## D7 `Occurrence` 暂留在 `cap/verify.py`

- 文档：§2 把 `Occurrence` 列为共享对象，应在 `schemas/objects.py`。
- 实现：它的 `context_kind` 依赖 DOM 扫描的类型，先留在 `cap/verify.py`；其余 8 个对象已在
  `schemas/objects.py`。
- 原因：现在上移会引入 `schemas → cap` 的反向依赖；等 `domscan` 的类型下沉到 schemas 后再搬。
- 需回写文档：否（阶段性）。

## D8 sqlite 表名用 `case_file`

- 文档：T04 六张表 `case/change/evidence/flow/probe/session`。
- 实现：`case` 是 sqlite 关键字，建表失败，改名为 `case_file`；其余五张表名不变。
- 原因：避免到处引号化；对外只暴露 `case_id`，不暴露表名。
- 需回写文档：是（T04 表名）。

## D9 trigger 主流程用确定性规划器

- 文档：trigger 由 planner（pydantic-ai）决定 P0–P6 的下一步。
- 实现：`dom/trigger.py` 用规则推进阶段；`Kernel` 已按"工具调用/证据/预算"抽好，
  接 LLM 时只替换"选择下一步"的函数，工具语义不变。
- 原因：先验证流程与证据链，再让模型介入；qwen 只用于测试，不宜作为流程正确性的前提。
- 需回写文档：是（T10 阶段实现顺序）。

## D10 trigger 的 P0/P1 顺序

- 文档：P0 `case_open`，P1 `source_read`。
- 实现：先 `source_read` 推断目标表，再 `case_open` 并登记 `write_targets`；阶段记录仍标 P0/P1。
- 原因：写闸门以 case 登记的写目标为准，先有目标才能建案（否则建完还要补登记）。
- 需回写文档：是（§8 P0/P1 说明）。

## D11 `db_write` 的 CONFLICT 只回 change_id

- 文档：`CONFLICT` 时"仍返回 change，便于回滚"。
- 实现：信封失败时没有 `data`，把 `change_id` 写进 message，并提示用 `db_undo --case` 回滚。
- 原因：保持统一信封形状（H9）优先于塞数据；change 已在库里，信息没丢。
- 需回写文档：是（§4.3 失败语义）。

## D12 写闸门以 case 登记的写目标为准

- 文档：`write_allow_tables` 由 profile yaml 决定。
- 实现：`allowed = profile.write_allow_tables ∪ case.write_targets`；trigger/inject 的
  profile 白名单默认为空，所以"没登记就拒绝"。
- 原因：每个 case 只该写它声明的表；yaml 作为运维级兜底。
- 需回写文档：是（§1.6 权限矩阵）。

## D13 inject 的 I7 清理语义

- 文档：I7 收尾 `db_undo` + `case_report`；undo 用于回滚自己造的前置数据。
- 实现：inject 的行是应用自己写进去的，因此 I7 用 `db_write DELETE`（按 tag）清除测试数据，
  并返回 `residue`（删除后仍匹配 tag 的行数，应为 0），change 记录保留可审计/可回滚。
- 原因：对"应用写入的行"调 `db_undo` 会把行还原，等于没清理；`residue` 在这里度量的是
  "自己造成的数据残留"，与 trigger 的 before_image 核对语义不同。
- 需回写文档：是（I7 说明）。

## D14 主 agent 先做确定性调度

- 文档：主 agent 由 LLM/planner 选择切片与下一步。
- 实现：`dom/main.py` 按 attempts→kind→路径排序，逐个 trigger→inject→归档；连续 3 次失败
  熔断 `BLOCKED_NEEDS_HUMAN`。`pick()` 是替换点，接 planner 时只改这里。
- 原因：先保证调度骨架、证据链与报告闭环，模型只影响"选哪个切片"。
- 需回写文档：是（M4 实现顺序）。

## D15 先做不依赖外部环境的工具

- 文档：36 工具按里程碑铺开。
- 实现：本轮先落地 `form_parse` / `context_classify` / `budget_solve` / `trace_diff` /
  `flow_lookup` / `artifact_save`——纯函数或只读本地 sqlite，不碰网络与目标库。
- 原因：先把"输入是数据不是命令"的解析面和长度预算打磨好，再挂探针/轨迹这类有状态工具。
- 需回写文档：否（实现顺序）。

## D16 `form_parse` 只做静态解析

- 文档：`form_parse` 支持静态与渲染两种。
- 实现：只接受 `html`；需要渲染后的 DOM 时由 agent 先 `http_request` 再传 `html`
  （H7：工具之间不互相调用）。
- 原因：渲染要浏览器，属于真实环境交互，放到 e2e 阶段。
- 需回写文档：是（§4.3 form_parse 输入）。

## D17 本地环境与模型细节不入库

- 文档：未规定环境信息放在哪里。
- 实现：开发机地址、测试容器名/镜像/挂载、端口映射、目标应用清单、模型端点与
  Key、数据库口令等只保存在仓库之外；仓库内只保留可复现的依赖清单
  （`impl/pyproject.toml`、`impl/deploy/apt-packages.txt`）与安装脚本。
- 原因：仓库是公开的（GitHub），这些信息既会泄露测试环境，也会随环境迁移而过期。
- 需回写文档：是（README「本地开发环境」一节说明该约定）。
