"""Lightweight HTML structure scan (pure function, no network).

Only implements what `verify_tag` / `context_classify` require:

* Element tree and sibling order (for ``node_path``);
* Raw offset -> containing element / attribute / comment;
* Context determination for text, attribute values, ``<script>``, ``<textarea>``, etc.

Deliberately avoids full HTML5 parsing—no malformed structure correction, no entity decoding;
Decoding is done on-demand in the verify rule layer to avoid inconsistencies.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field

VOID_ELEMENTS: frozenset[str] = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

RAWTEXT_ELEMENTS: frozenset[str] = frozenset({"script", "style", "textarea", "title"})

_START_TAG = re.compile(
    r"<([A-Za-z][A-Za-z0-9:_-]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>",
    re.DOTALL,
)
_END_TAG = re.compile(r"</\s*([A-Za-z][A-Za-z0-9:_-]*)\s*>")
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_ATTR = re.compile(
    r"""([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*)))?""",
    re.DOTALL,
)
_RAW_CLOSE = re.compile(r"</\s*([A-Za-z][A-Za-z0-9:_-]*)\s*>", re.IGNORECASE)

_QUOTE_TEXT: dict[str, str] = {"double": '"', "single": "'", "none": ""}


@dataclass(slots=True)
class Attr:
    name: str
    value: str
    quote: str  # "double" | "single" | "none"
    start: int  # Start position of the value in the original text
    end: int


@dataclass(slots=True)
class Node:
    tag: str
    attrs: dict[str, str]
    attr_quotes: dict[str, str]
    attr_ranges: dict[str, tuple[int, int]]
    start: int
    start_tag_end: int
    parent: Node | None = None
    children: list[Node] = field(default_factory=list)
    end: int = 0

    def get(self, name: str) -> str | None:
        return self.attrs.get(name.lower())

    def has(self, name: str) -> bool:
        return name.lower() in self.attrs

    @property
    def text(self) -> str:
        return ""


@dataclass(slots=True)
class Segment:
    kind: str  # text | attr | comment
    start: int
    end: int
    node: Node | None
    attr_name: str | None = None
    quote: str = "none"


@dataclass(slots=True)
class Document:
    html: str
    nodes: list[Node]
    segments: list[Segment]
    _starts: list[int] = field(default_factory=list)

    def segment_at(self, pos: int) -> Segment | None:
        """Returns the innermost fragment containing ``pos``; returns None if out of bounds."""
        idx = bisect_right(self._starts, pos) - 1
        if idx < 0:
            return None
        segment = self.segments[idx]
        if segment.start <= pos < segment.end:
            return segment
        return None

    def node_at(self, pos: int) -> Node | None:
        segment = self.segment_at(pos)
        if segment is None:
            return None
        if segment.node is not None:
            return segment.node
        # When the landing point is between text/attribute fragments (inside a tag), fall back to the nearest opened element.
        best: Node | None = None
        for node in self.nodes:
            if node.start <= pos < node.end and (best is None or node.start >= best.start):
                best = node
        return best


def _parse_attrs(raw: str, base: int) -> list[Attr]:
    attrs: list[Attr] = []
    for match in _ATTR.finditer(raw):
        name = match.group(1).lower()
        for group_index, quote in ((2, "double"), (3, "single"), (4, "none")):
            value = match.group(group_index)
            if value is not None:
                start = base + match.start(group_index)
                attrs.append(
                    Attr(
                        name=name,
                        value=value,
                        quote=quote,
                        start=start,
                        end=start + len(value),
                    )
                )
                break
        else:
            attrs.append(Attr(name=name, value="", quote="none", start=base, end=base))
    return attrs


def _flush_text(
    segments: list[Segment], html: str, start: int, end: int, node: Node | None
) -> None:
    if end > start:
        segments.append(Segment(kind="text", start=start, end=end, node=node))


def parse(html: str) -> Document:
    """Scans HTML into an element tree + fragment table. Malformed input does not raise errors; best-effort based on encountered structure."""
    nodes: list[Node] = []
    segments: list[Segment] = []
    stack: list[Node] = []
    roots: list[Node] = []

    def current() -> Node | None:
        return stack[-1] if stack else None

    i = 0
    text_start = 0
    n = len(html)
    while i < n:
        char = html[i]
        if char != "<":
            i += 1
            continue

        comment = _COMMENT.match(html, i)
        if comment is not None:
            _flush_text(segments, html, text_start, i, current())
            segments.append(
                Segment(
                    kind="comment",
                    start=comment.start(),
                    end=comment.end(),
                    node=current(),
                )
            )
            i = text_start = comment.end()
            continue

        end_tag = _END_TAG.match(html, i)
        if end_tag is not None:
            _flush_text(segments, html, text_start, i, current())
            name = end_tag.group(1).lower()
            for depth in range(len(stack) - 1, -1, -1):
                if stack[depth].tag == name:
                    while len(stack) > depth:
                        node = stack.pop()
                        node.end = end_tag.end()
                    break
            i = text_start = end_tag.end()
            continue

        start_tag = _START_TAG.match(html, i)
        if start_tag is not None:
            _flush_text(segments, html, text_start, i, current())
            name = start_tag.group(1).lower()
            raw_attrs = start_tag.group(2)
            attrs = _parse_attrs(raw_attrs, start_tag.start(2))
            node = Node(
                tag=name,
                attrs={a.name: a.value for a in attrs},
                attr_quotes={a.name: a.quote for a in attrs},
                attr_ranges={a.name: (a.start, a.end) for a in attrs},
                start=i,
                start_tag_end=start_tag.end(),
                parent=current(),
            )
            nodes.append(node)
            if node.parent is not None:
                node.parent.children.append(node)
            else:
                roots.append(node)

            for attr in attrs:
                if attr.end > attr.start:
                    segments.append(
                        Segment(
                            kind="attr",
                            start=attr.start,
                            end=attr.end,
                            node=node,
                            attr_name=attr.name,
                            quote=attr.quote,
                        )
                    )

            self_closing = raw_attrs.rstrip().endswith("/")
            i = text_start = start_tag.end()

            if name in RAWTEXT_ELEMENTS and not self_closing:
                stack.append(node)
                close = _RAW_CLOSE.search(html, i)
                close_start = close.start() if close is not None else n
                _flush_text(segments, html, i, close_start, node)
                if close is not None:
                    node.end = close.end()
                    stack.pop()
                    i = text_start = close.end()
                else:
                    node.end = n
                    i = text_start = n
                continue

            if name not in VOID_ELEMENTS and not self_closing:
                stack.append(node)
            else:
                node.end = start_tag.end()
            continue

        i += 1

    _flush_text(segments, html, text_start, n, current())
    while stack:
        stack.pop().end = n

    ordered = sorted(segments, key=lambda segment: segment.start)
    document = Document(html=html, nodes=nodes, segments=ordered)
    document._starts = [segment.start for segment in ordered]
    return document


# ---------------------------------------------------------------------------
# Selectors and evidence fragments
# ---------------------------------------------------------------------------


def _first_class(node: Node) -> str | None:
    raw = node.get("class")
    if not raw:
        return None
    return raw.split()[0] if raw.split() else None


def _selector(node: Node, *, with_nth: bool) -> str:
    name = node.tag.lower()
    node_id = node.get("id")
    if node_id:
        base = f"{name}#{node_id}"
    else:
        cls = _first_class(node)
        base = f"{name}.{cls}" if cls else name
    if with_nth and node.parent is not None:
        same = [child for child in node.parent.children if child.tag == node.tag]
        if len(same) > 1:
            index = same.index(node) + 1
            base += f":nth-of-type({index})"
    return base


def node_path(node: Node) -> str:
    chain: list[Node] = []
    cursor: Node | None = node
    while cursor is not None:
        chain.append(cursor)
        cursor = cursor.parent
    return ">".join(_selector(item, with_nth=True) for item in reversed(chain))


def dom_ancestors(node: Node) -> list[str]:
    chain: list[Node] = []
    cursor: Node | None = node
    while cursor is not None:
        chain.append(cursor)
        cursor = cursor.parent
    return [_selector(item, with_nth=False) for item in reversed(chain)]


CHAIN_LIMIT = 4096


def chain_html(html: str, node: Node, marker_start: int, marker_end: int) -> tuple[str, bool]:
    """Returns the full fragment of ancestor elements; retains ±800 bytes around the marker if exceeding 4KB."""
    snippet = html[node.start : node.end]
    if len(snippet) <= CHAIN_LIMIT:
        return snippet, False
    rel_start = max(0, marker_start - node.start - 800)
    rel_end = min(len(snippet), marker_end - node.start + 800)
    return snippet[rel_start:rel_end], True


# ---------------------------------------------------------------------------
# Context determination
# ---------------------------------------------------------------------------


def js_string_state(code: str, offset: int) -> tuple[str, str]:
    """Determines if the offset in ``<script>`` is located within a string literal.

    Returns ``(state, quote)``, state ∈ code|string|line_comment|block_comment.
    """
    state = "code"
    quote = ""
    i = 0
    while i < offset:
        char = code[i]
        nxt = code[i + 1] if i + 1 < len(code) else ""
        if state == "code":
            if char in "'\"`":
                state, quote = "string", char
            elif char == "/" and nxt == "/":
                state = "line_comment"
                i += 1
            elif char == "/" and nxt == "*":
                state = "block_comment"
                i += 1
        elif state == "string":
            if char == "\\":
                i += 1
            elif char == quote:
                state, quote = "code", ""
        elif state == "line_comment":
            if char == "\n":
                state = "code"
        else:  # block_comment
            if char == "*" and nxt == "/":
                state = "code"
                i += 1
        i += 1
    return state, quote


@dataclass(slots=True)
class Context:
    kind: str
    quoting: str  # double | single | none
    node: Node | None
    js_state: str | None = None
    attr_name: str | None = None
    #: True when the landing point sits inside a start tag but outside any quoted value
    #: (i.e. in attribute-name space). Markup written there is parsed as more attributes,
    #: never as a new element, so it cannot execute.
    in_tag: bool = False


def classify(document: Document, pos: int, *, content_type: str = "text/html") -> Context:
    """Determines the context_kind of ``pos`` from inner to outer (Acceptance Spec §5)."""
    html = document.html
    segment = document.segment_at(pos)
    node = document.node_at(pos)

    # text/plain has highest priority: even if the response body is complete HTML, the browser does not parse it.
    if not is_html_content_type(content_type):
        return Context(kind="plain_text", quoting="none", node=node)

    if segment is not None and segment.kind == "comment":
        return Context(kind="comment", quoting="none", node=segment.node or node)

    if segment is not None and segment.kind == "attr" and segment.node is not None:
        return Context(
            kind="attr",
            quoting=segment.quote,
            node=segment.node,
            js_state=None,
            attr_name=segment.attr_name,
        )

    if segment is None:
        holder = _start_tag_at(document, pos)
        if holder is not None:
            return Context(
                kind="attr",
                quoting="none",
                node=holder,
                attr_name=None,
                in_tag=True,
            )

    owner = _owner_for_position(document, pos)
    if owner is None:
        return Context(kind="html_text", quoting="none", node=node)

    tag = owner.tag
    if tag == "script":
        script_type = (owner.get("type") or "").lower()
        if "json" in script_type:
            return Context(kind="json", quoting="none", node=owner)
        content_start = owner.start_tag_end
        state, quote = js_string_state(html[content_start:], pos - content_start)
        if state == "string":
            quoting = "double" if quote == '"' else ("single" if quote == "'" else "none")
            return Context(
                kind="script_string", quoting=quoting, node=owner, js_state=state
            )
        if state in {"line_comment", "block_comment"}:
            return Context(
                kind="script_block", quoting="none", node=owner, js_state=state
            )
        return Context(kind="script_block", quoting="none", node=owner, js_state=state)
    if tag == "style":
        return Context(kind="attr", quoting="none", node=owner, js_state="style")
    if tag == "textarea":
        return Context(kind="textarea", quoting="none", node=owner)
    if tag == "title":
        return Context(kind="html_text", quoting="none", node=owner)
    if tag == "pre":
        return Context(kind="plain_text", quoting="none", node=owner)
    return Context(kind="html_text", quoting="none", node=owner)


def _start_tag_at(document: Document, pos: int) -> Node | None:
    """Innermost element whose start tag spans ``pos`` (attribute-name space)."""
    holder: Node | None = None
    for node in document.nodes:
        if node.start <= pos < node.start_tag_end and (
            holder is None or node.start >= holder.start
        ):
            holder = node
    return holder


def _owner_for_position(document: Document, pos: int) -> Node | None:
    """Returns the innermost element at the raw offset whose content includes that offset."""
    best: Node | None = None
    for node in document.nodes:
        if node.start_tag_end <= pos < node.end and (
            best is None or node.start >= best.start
        ):
            best = node
    if best is None and document.segment_at(pos) is not None:
        segment = document.segment_at(pos)
        if segment is not None:
            best = segment.node
    return best


def is_html_content_type(content_type: str) -> bool:
    lowered = content_type.split(";")[0].strip().lower()
    return lowered in {"text/html", "application/xhtml+xml", ""}


def echo_snapshot(html: str, tag: str, *, before: int = 120, after: int = 120, max_len: int = 4000) -> str:
    """Return only the markup that directly wraps the echoed tag.

    A whole response page is mostly noise and truncating it can cut exactly the
    quote or comment that decides whether the payload is inert. This keeps the
    tag occurrence plus its enclosing chain (start tags, quote, comment or
    script string) and drops sibling content.
    """
    position = html.find(tag)
    if position < 0:
        return ""
    document = parse(html)
    segment = document.segment_at(position)
    inner = html[max(0, position - before) : position + len(tag) + after]
    if segment is None:
        return inner[:max_len]
    if segment.kind == "comment":
        return f"<!-- ... {inner} ... -->"[:max_len]
    node = segment.node
    if segment.kind == "attr" and node is not None:
        name = segment.attr_name or ""
        quote = _QUOTE_TEXT.get(segment.quote or "", "")
        value = html[segment.start : segment.end]
        opening = "".join(
            f" {other}={_QUOTE_TEXT.get(q, '')}{node.attrs[other]}{_QUOTE_TEXT.get(q, '')}"
            for other, q in node.attr_quotes.items()
            if other != name
        )
        text = f"<{node.tag}{opening} {name}={quote}{value}{quote}>"
        if not html[segment.start : segment.end + 1].endswith(quote):
            text += "  [attribute value is not closed after the payload]"
        return text[:max_len]
    if node is None:
        return inner[:max_len]
    closing = f"</{node.tag}>"
    node_end = node.end - len(closing) if html[node.end - len(closing) : node.end].lower() == closing else node.end
    inner_start = max(node.start_tag_end, position - before)
    inner_end = min(node_end, position + len(tag) + after)
    inner = html[inner_start:inner_end]
    chain: list[Node] = []
    current: Node | None = node
    while current is not None:
        if current.tag not in {"html", "body"}:
            chain.append(current)
        current = current.parent
    opened = "".join(f"<{item.tag}>" for item in reversed(chain))
    closed = "".join(f"</{item.tag}>" for item in chain)
    text = opened + inner + closed
    if node.tag in {"script", "style", "textarea", "title"}:
        text += f"\n[payload sits inside <{node.tag}>; the closing sequence decides execution]"
    return text[:max_len]
