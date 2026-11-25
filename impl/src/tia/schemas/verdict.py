"""verdict 枚举：各 agent 的判定词表（闭集）。

注意：``verify_tag`` **不**返回 verdict，只返回 ``verdict_ceiling``；verdict 由
各 agent 的 judge 计算（H5）。三个词表互不混用，报告里会标明来源 agent。
"""

from __future__ import annotations

from enum import StrEnum


class TriggerVerdict(StrEnum):
    """触发 agent 的判定（《触发 Agent 文档》§verdict）。"""

    NOT_EXECUTED = "NOT_EXECUTED"
    SQL_ERROR = "SQL_ERROR"
    READ_EMPTY = "READ_EMPTY"
    READ_NOT_REFLECTED = "READ_NOT_REFLECTED"
    REFLECTED_ENCODED = "REFLECTED_ENCODED"
    REFLECTED_INERT = "REFLECTED_INERT"
    REFLECTED_ESCAPED = "REFLECTED_ESCAPED"
    BLOCKED_CSP = "BLOCKED_CSP"
    EXECUTED = "EXECUTED"


class InjectVerdict(StrEnum):
    """注入 agent 的判定（《注入 Agent 文档》§I6 三态矩阵）。"""

    BASELINE_DIRTY = "BASELINE_DIRTY"
    PATH_UNREACHABLE = "PATH_UNREACHABLE"
    NO_HTTP_ENTRY = "NO_HTTP_ENTRY"
    ENTRY_AMBIGUOUS = "ENTRY_AMBIGUOUS"
    WRITE_NOT_REACHED = "WRITE_NOT_REACHED"
    CONSTRAINT_UNSAT = "CONSTRAINT_UNSAT"
    UNKNOWN_TRANSFORM = "UNKNOWN_TRANSFORM"
    TYPE_COERCED = "TYPE_COERCED"
    LENGTH_EXCEEDED = "LENGTH_EXCEEDED"
    WRITTEN_NOT_VISIBLE = "WRITTEN_NOT_VISIBLE"
    OUTPUT_FILTERED = "OUTPUT_FILTERED"
    NOT_EXECUTABLE = "NOT_EXECUTABLE"
    EXECUTABLE = "EXECUTABLE"
    ENV_ERROR = "ENV_ERROR"
    AUTH_BLOCKED = "AUTH_BLOCKED"


class MainVerdict(StrEnum):
    """主 agent 的调度结论；只进调度统计，永不进报告安全结论。"""

    ARCHIVED_EXECUTABLE = "ARCHIVED_EXECUTABLE"
    ARCHIVED_FAILED = "ARCHIVED_FAILED"
    HANDOFF_INCOMPLETE = "HANDOFF_INCOMPLETE"
    SKIPPED_BUDGET = "SKIPPED_BUDGET"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"
    SKIPPED_UNREADABLE = "SKIPPED_UNREADABLE"
    BLOCKED_NEEDS_HUMAN = "BLOCKED_NEEDS_HUMAN"


class VerdictCeiling(StrEnum):
    """verify_tag 能证明的上限，不是安全结论。"""

    EXECUTABLE = "EXECUTABLE"
