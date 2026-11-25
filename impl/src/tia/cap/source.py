"""Source and entry: source_read / source_grep.

Lightweight lexical markers (``in_string`` / ``in_comment``) only hint at "the approximate state of this line",
not a parser; when uncertain, prefer returning false over outputting a misleading true.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.cap.registry import ToolOutput
from tia.inf.runtime import get_runtime
from tia.schemas.envelope import ErrorCode, ToolError

MAX_LINES = 500


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"Invalid parameter: {exc.errors()[0]['msg']}") from exc


class SourceReadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    line_from: int | None = Field(default=None, ge=1)
    line_to: int | None = Field(default=None, ge=1)
    around: dict[str, int] | None = None


class SourceGrepInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: str
    path: str = "."
    glob: str = "*.php"
    context: int = Field(default=2, ge=0, le=10)
    max: int = Field(default=50, ge=1, le=200)
    fixed: bool = False
    ignore_case: bool = False


def _scan_states(lines: list[tuple[int, str]]) -> list[dict[str, Any]]:
    """Provide in_comment / in_string per line (simplified PHP lexical analysis)."""
    in_block_comment = False
    quote: str | None = None
    result: list[dict[str, Any]] = []
    for _, text in lines:
        idx = 0
        line_in_string = quote is not None
        line_in_comment = in_block_comment
        while idx < len(text):
            ch = text[idx]
            nxt = text[idx + 1] if idx + 1 < len(text) else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    idx += 2
                    continue
                idx += 1
                continue
            if quote is not None:
                if ch == "\\":
                    idx += 2
                    continue
                if ch == quote:
                    quote = None
                idx += 1
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                line_in_comment = True
                idx += 2
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "#":
                break
            if ch in "'\"":
                quote = ch
                line_in_string = True
            idx += 1
        result.append({"in_comment": line_in_comment, "in_string": line_in_string})
    return result


async def source_read(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(SourceReadInput, arguments)
    rt = get_runtime()

    if params.around is not None:
        center = int(params.around.get("line", 1))
        span = int(params.around.get("n", 40))
        line_from = center - span
        line_to = center + span
    else:
        line_from = params.line_from
        line_to = params.line_to
        if line_from is None or line_to is None:
            raise _bad("line_from/line_to or around is required")
        if line_to < line_from:
            raise _bad("line_to must be >= line_from")
    if line_to - line_from + 1 > MAX_LINES:
        raise _bad(f"Range exceeds {MAX_LINES} lines", "use around or narrow the range")

    from tia.ad.fs import FsAdapter

    adapter = FsAdapter(rt.settings.app_root)
    slice_ = adapter.read(params.file, line_from, line_to)
    states = _scan_states(slice_.lines)
    lines = [
        {"n": n, "text": text, "in_comment": state["in_comment"], "in_string": state["in_string"]}
        for (n, text), state in zip(slice_.lines, states, strict=True)
    ]
    return ToolOutput(
        data={
            "file": slice_.path,
            "total_lines": slice_.total_lines,
            "sha256": slice_.sha256,
            "lines": lines,
        }
    )


async def source_grep(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(SourceGrepInput, arguments)
    rt = get_runtime()

    from tia.ad.fs import FsAdapter

    adapter = FsAdapter(rt.settings.app_root)
    hits, truncated, scanned = adapter.grep(
        params.pattern,
        params.path,
        glob=params.glob,
        context=params.context,
        max_hits=params.max,
        fixed=params.fixed,
        ignore_case=params.ignore_case,
    )
    return ToolOutput(
        data={"hits": hits, "truncated": truncated, "scanned_files": scanned},
        warnings=["TRUNCATED"] if truncated else [],
    )
