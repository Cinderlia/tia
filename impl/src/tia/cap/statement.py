"""Resolve the SQL statement a query call executes and the request fields feeding it.

A NAVI sink often points at the *call* line (``$link->query($sql)``) while the
statement itself is assembled a few lines above.  Interpreting the call line as
the statement is wrong for context (a call carries no quotes) and for the
payload carrier (the call carries no request variable).  Both questions are
answered generically here, from the file text around the sink, without knowing
anything about a particular application:

* :func:`statement_origin` follows the local variable passed to the call back to
  the assignment (and ``.=`` appends) that builds it;
* :func:`request_carriers` intersects the page's form fields with the request
  inputs that reach that statement, directly (``$_POST['x']``) or through a
  local alias (``$x = $_POST['x']``).
"""

from __future__ import annotations

import re

#: A statement is worth following only when it looks like SQL.
_SQL_KEYWORD = re.compile(r"\b(?:select|insert|update|delete|replace)\b", re.IGNORECASE)

#: ``$link->query($sql)`` / ``$pdo->prepare($sql)`` — the statement is the argument.
_CALL = re.compile(
    r"\$(\w+)\s*->\s*(?:query|prepare|exec|execute)\s*\(\s*\$(\w+)\s*[,)]"
)
#: ``$link->query("UPDATE ...")`` — the statement is written inline at the call.
_INLINE_CALL = re.compile(
    r"\$(\w+)\s*->\s*(?:query|prepare|exec|execute)\s*\(", re.IGNORECASE
)
_ASSIGN = re.compile(r"^\s*\$(\w+)\s*=\s*(.*)$")
_APPEND = re.compile(r"^\s*\$(\w+)\s*\.=\s*(.*)$")

#: ``$_POST['name']``, ``$_GET["name"]``, ``$_REQUEST['name']``.
_REQUEST = re.compile(r"\$_(?:POST|GET|REQUEST)\s*\[\s*['\"](\w+)['\"]\s*\]")
#: ``$local = <anything> $_POST['name']`` — a local alias of a request input.
_ALIAS = re.compile(
    r"\$(\w+)\s*=\s*[^;\n]*\$_(?:POST|GET|REQUEST)\s*\[\s*['\"](\w+)['\"]"
)
_VARIABLE = re.compile(r"\$(\w+)")

#: How far above the call line a statement may be assembled, in lines.
_ORIGIN_WINDOW = 60


def statement_origin(
    lines: list[tuple[int, str]], call_line: int, call_code: str = ""
) -> tuple[str, int]:
    """Return ``(statement_text, line)`` for the statement executed at ``call_line``.

    ``lines`` is the file window as ``(line_number, text)`` pairs.  The statement
    text is the assignment (plus any ``.=`` appends) of the variable passed to the
    call.  When the call cannot be resolved, the call line itself is returned so
    the caller keeps its previous behaviour.
    """

    argument = _call_argument(call_code)
    if argument is None:
        for number, text in lines:
            if number == call_line:
                argument = _call_argument(text)
                break
    if argument is None:
        return _inline_statement(lines, call_line) or (call_code, call_line)

    window = [
        (number, text)
        for number, text in sorted(lines)
        if call_line - _ORIGIN_WINDOW <= number < call_line
    ]
    parts: list[str] = []
    origin_line = call_line
    pending_cont = False
    for number, text in reversed(window):
        appended = _APPEND.match(text)
        assigned = _ASSIGN.match(text)
        if appended is not None and appended.group(1) == argument:
            parts.append(appended.group(2))
            origin_line = number
            pending_cont = True
            continue
        if assigned is not None and assigned.group(1) == argument:
            parts.append(assigned.group(2))
            origin_line = number
            break
        if pending_cont and text.strip().startswith((".", '"', "'")):
            # A concatenation continuation line belongs to the fragment above it.
            parts.append(text)
            origin_line = number
            continue
        pending_cont = False

    if not parts:
        return call_code, call_line
    statement = "\n".join(reversed(parts))
    if not _SQL_KEYWORD.search(statement):
        return call_code, call_line
    return statement, origin_line


def _inline_statement(
    lines: list[tuple[int, str]], call_line: int
) -> tuple[str, int] | None:
    """Return a statement written literally inside the query call at ``call_line``.

    Some call sites pass a concatenated string straight to ``query()``.  Reading
    only the call line would see no SQL; the statement spans the following lines
    until the call's parentheses close.  PHP concatenation is collapsed to a
    placeholder so the result still looks like a single SQL statement.
    """

    ordered = sorted(lines)
    start = None
    for index, (number, text) in enumerate(ordered):
        if number == call_line and _INLINE_CALL.search(text):
            start = index
            break
    if start is None:
        return None
    collected: list[str] = []
    depth = 0
    seen_open = False
    for _number, text in ordered[start:]:
        position = _INLINE_CALL.search(text)
        body = text[position.end() :] if (position and not seen_open) else text
        for ch in body:
            if ch == "(":
                depth += 1
                seen_open = True
            elif ch == ")":
                depth -= 1
        collected.append(body)
        if seen_open and depth <= 0:
            break
    raw = " ".join(collected)
    raw = re.sub(r"['\"]\s*\.\s*", "", raw)
    raw = re.sub(r"\s*\.\s*['\"]", "", raw)
    raw = raw.replace('"', " ")
    raw = re.sub(r"\s+", " ", raw).strip()
    while raw.endswith((")", ";")):
        raw = raw[:-1].rstrip()
    if not _SQL_KEYWORD.search(raw):
        return None
    return raw, call_line


def sql_literals(text: str) -> str:
    """Join the SQL string literals of a window, ignoring the PHP around them.

    A statement is often spread over an assignment and later ``.=`` appends, with
    request values spliced between the fragments.  Concatenating only the quoted
    fragments keeps the SQL keywords and the literal predicates, which is what a
    reachability check needs.
    """

    fragments: list[str] = []
    for match in re.finditer(r'"([^"]*)"|\'([^\']*)\'', text):
        fragment = match.group(1) if match.group(1) is not None else match.group(2)
        if _SQL_KEYWORD.search(fragment) or re.search(
            r"\b(?:and|or|where|order\s+by|limit)\b", fragment, re.IGNORECASE
        ):
            fragments.append(fragment.strip())
    return " ".join(fragments)


def request_carriers(
    source_text: str, statement_text: str, field_names: list[str]
) -> list[str]:
    """Form fields that can carry a value into ``statement_text``, in form order.

    A field qualifies when its name is a request input used by the statement, or
    when a local alias of that input (``$entry = sqli($_POST['entry'])``) appears
    in the statement.  The result is a static prior; the prover still has to send
    the request and observe the executed SQL.
    """

    used = set(_VARIABLE.findall(statement_text))
    in_statement = set(_REQUEST.findall(statement_text))
    aliases: dict[str, str] = {}
    for local, field in _ALIAS.findall(source_text):
        aliases[local] = field
    flowing = {field for local, field in aliases.items() if local in used}
    return [name for name in field_names if name in in_statement or name in flowing]


def _call_argument(code: str) -> str | None:
    match = _CALL.search(code or "")
    return match.group(2) if match else None
