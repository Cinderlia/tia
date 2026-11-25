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
