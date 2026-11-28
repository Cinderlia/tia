"""Discover the request shapes a page and its source expose.

An entry point is not always a ``<form>``: admin panels post through AJAX
endpoints, REST routes, ``admin-post.php`` handlers or plain links that carry
query parameters.  This module turns the evidence we already have (page markup,
inline scripts, source window, observed requests) into ``RequestTemplate``
values that the planner can pick from and the injector can execute.

Discovery is best effort and bounded.  It never sends a request; it only says
"this request shape exists, here is where the evidence came from".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from tia.cap.domscan import parse
from tia.cap.forms import forms_from_document

MAX_ENDPOINTS = 24
MAX_LINKS = 40
_ASSET = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4|pdf)(?:\?|$)",
    re.IGNORECASE,
)
_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "#")
_HIDDEN_INPUT = re.compile(
    r"<input\b(?=[^>]*\bname\s*=\s*[\"'](?P<name>[^\"']+)[\"'])"
    r"(?=[^>]*\bvalue\s*=\s*[\"'](?P<value>[^\"']*)[\"'])[^>]*>",
    re.IGNORECASE,
)
_JS_ASSIGN = re.compile(
    r"(?:var\s+|let\s+|const\s+)?[\"']?(?P<name>[A-Za-z_$][\w$]*)[\"']?\s*[:=]\s*"
    r"[\"'](?P<value>[^\"']{1,300})[\"']"
)
_JS_URL = re.compile(
    r"[\"'](?P<url>(?:https?://[^\"'\s]+|/[^\"'\s]{1,200}|[A-Za-z0-9_\-./]{1,120}\.php"
    r"(?:\?[^\"'\s]*)?))[\"']"
)
_JS_POST = re.compile(
    r"(?:\$\.post|\$\.get|fetch|axios\.(?:post|get)|\.open)\s*\(\s*"
    r"[\"'](?P<url>[^\"']+)[\"'](?:\s*,\s*\{(?P<fields>[^{}]{0,600})\})?",
    re.IGNORECASE,
)
_ACTION_REF = re.compile(r"(?:\?|&)action=(?P<name>[A-Za-z0-9_\-]{1,64})")
_ACTION_VALUE = re.compile(
    r"\baction\b\s*[:=]\s*[\"'](?P<name>[A-Za-z0-9_\-]{1,64})[\"']"
)
_WP_AJAX_HOOK = re.compile(r"wp_ajax(?:_nopriv)?_(?P<name>[A-Za-z0-9_]{1,64})")
_ADMIN_POST = re.compile(r"admin-post\.php")
_ADMIN_AJAX = re.compile(r"admin-ajax\.php")
_AJAX_WORD = re.compile(r"\bajaxurl\b|\badmin-ajax\b", re.IGNORECASE)
_FORM_FIELD = re.compile(
    r"[\"']?(?P<name>[A-Za-z_][\w\-\[\]]{0,60})[\"']?\s*:\s*"
    r"(?:\"[^\"]{0,120}\"|'[^']{0,120}'|\d{1,18}|true|false|null)"
)


@dataclass
class NonceSource:
    """Where a request token can be read from before the request is sent."""

    kind: str = "hidden_input"  # hidden_input | js_var
    page_url: str = ""
    name: str = ""
    pattern: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "page_url": self.page_url,
            "name": self.name,
            "pattern": self.pattern,
        }


@dataclass
class RequestTemplate:
    """One request shape that the page, its scripts or its source expose."""

    method: str
    url: str
    fields: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    nonces: list[NonceSource] = field(default_factory=list)
    origin: str = "page"  # form | link | script | source | ajax
    evidence: str = ""

    @property
    def names(self) -> set[str]:
        names = set(self.fields)
        names.update(name for name, _ in parse_qsl(urlsplit(self.url).query))
        return names

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "fields": self.fields,
            "headers": self.headers,
            "nonces": [item.to_dict() for item in self.nonces],
            "origin": self.origin,
            "evidence": self.evidence[:300],
        }


def extract_token(html: str, source: NonceSource) -> str:
    """Read one token value out of a page, or return an empty string."""
    if not html:
        return ""
    if source.pattern:
        match = re.search(source.pattern, html)
        if match:
            return match.group(1) if match.groups() else match.group(0)
    for match in _HIDDEN_INPUT.finditer(html):
        if match.group("name") == source.name:
            return match.group("value")
    for match in _JS_ASSIGN.finditer(html):
        if match.group("name") == source.name:
            return match.group("value")
    return ""


def _same_origin(url: str, page_url: str) -> bool:
    left, right = urlsplit(url), urlsplit(page_url)
    return (left.scheme, left.netloc) == (right.scheme, right.netloc)


def _normalize(url: str, page_url: str) -> str:
    joined = urljoin(page_url, url.strip())
    parts = urlsplit(joined)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _usable(url: str, page_url: str) -> bool:
    if not url or any(url.lower().startswith(item) for item in _SKIP_SCHEMES):
        return False
    if _ASSET.search(url):
        return False
    return _same_origin(url, page_url)


def _fields_from_object(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _FORM_FIELD.finditer(text or ""):
        name = match.group("name")
        if len(fields) < 40 and name not in fields:
            fields[name] = ""
    return fields


def _nonces_from(html: str, page_url: str) -> list[NonceSource]:
    nonces: list[NonceSource] = []
    for match in _HIDDEN_INPUT.finditer(html or ""):
        name = match.group("name")
        lowered = name.lower()
        if any(marker in lowered for marker in ("nonce", "token", "csrf", "_wp")):
            nonces.append(NonceSource(kind="hidden_input", page_url=page_url, name=name))
    for match in _JS_ASSIGN.finditer(html or ""):
        name = match.group("name")
        lowered = name.lower()
        if "nonce" in lowered or "token" in lowered:
            nonces.append(NonceSource(kind="js_var", page_url=page_url, name=name))
    seen: set[tuple[str, str]] = set()
    unique: list[NonceSource] = []
    for item in nonces:
        key = (item.kind, item.name)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def endpoints_from_html(html: str, page_url: str) -> list[RequestTemplate]:
    """Collect forms, query links and script-called URLs from one page."""
    found: list[RequestTemplate] = []
    document = parse(html or "")
    for page_form in forms_from_document(document, page_url):
        fields = {entry.name: entry.value or "" for entry in page_form.fields}
        found.append(
            RequestTemplate(
                method=page_form.method.upper(),
                url=page_form.action or page_url,
                fields=fields,
                nonces=[
                    NonceSource(kind="hidden_input", page_url=page_url, name=name)
                    for name in fields
                    if any(marker in name.lower() for marker in ("nonce", "token", "csrf"))
                ],
                origin="form",
                evidence=f"form {page_form.method.upper()} {page_form.action}",
            )
        )
    links = re.findall(
        r"<a\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"']", html or "", re.IGNORECASE
    )
    for href in links[:MAX_LINKS]:
        url = _normalize(href, page_url)
        if not _usable(url, page_url) or "?" not in url:
            continue
        found.append(
            RequestTemplate(
                method="GET",
                url=url,
                fields={name: "" for name, _ in parse_qsl(urlsplit(url).query)},
                origin="link",
                evidence=f"link {href}"[:300],
            )
        )
    scripts = " ".join(
        re.findall(r"<script\b[^>]*>(.*?)</script>", html or "", re.IGNORECASE | re.DOTALL)
    )
    for match in _JS_POST.finditer(scripts):
        url = _normalize(match.group("url"), page_url)
        if not _usable(url, page_url):
            continue
        fields = _fields_from_object(match.group("fields") or "")
        found.append(
            RequestTemplate(
                method="POST",
                url=url,
                fields=fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                origin="script",
                evidence=match.group(0)[:300],
            )
        )
    for match in _JS_URL.finditer(scripts):
        url = _normalize(match.group("url"), page_url)
        if not _usable(url, page_url) or "?" not in url:
            continue
        found.append(
            RequestTemplate(
                method="GET",
                url=url,
                fields={name: "" for name, _ in parse_qsl(urlsplit(url).query)},
                origin="script",
                evidence=match.group(0)[:300],
            )
        )
    return _dedupe(found)


def endpoints_from_source(
    text: str, page_url: str, *, base_url: str | None = None
) -> list[RequestTemplate]:
    """Collect request shapes named by the source window (actions, endpoints)."""
    base = base_url or page_url
    parts = urlsplit(base)
    root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    found: list[RequestTemplate] = []
    action_hints: list[tuple[str, str]] = []
    for match in _ACTION_REF.finditer(text or ""):
        action_hints.append((match.group("name"), match.group(0)))
    for match in _ACTION_VALUE.finditer(text or ""):
        action_hints.append((match.group("name"), match.group(0)))
    for match in _WP_AJAX_HOOK.finditer(text or ""):
        action_hints.append((match.group("name"), match.group(0)))
    for name, evidence in action_hints:
        if _ADMIN_POST.search(text or ""):
            url = f"{root.rstrip('/')}/wp-admin/admin-post.php?action={name}"
        elif _ADMIN_AJAX.search(text or "") or (
            _AJAX_WORD.search(text or "") and "/wp-admin/" in parts.path
        ):
            url = f"{root.rstrip('/')}/wp-admin/admin-ajax.php?action={name}"
        else:
            separator = "&" if "?" in base else "?"
            url = f"{base}{separator}action={name}"
        found.append(
            RequestTemplate(
                method="POST",
                url=url,
                fields={"action": name},
                origin="ajax",
                evidence=evidence[:200],
            )
        )
    for match in _JS_POST.finditer(text or ""):
        url = _normalize(match.group("url"), base)
        if not _usable(url, base):
            continue
        found.append(
            RequestTemplate(
                method="POST",
                url=url,
                fields=_fields_from_object(match.group("fields") or ""),
                origin="source",
                evidence=match.group(0)[:300],
            )
        )
    for match in _JS_URL.finditer(text or ""):
        url = _normalize(match.group("url"), base)
        if not _usable(url, base) or "?" not in url:
            continue
        found.append(
            RequestTemplate(
                method="GET",
                url=url,
                fields={name: "" for name, _ in parse_qsl(urlsplit(url).query)},
                origin="source",
                evidence=match.group(0)[:300],
            )
        )
    return _dedupe(found)


def _dedupe(items: list[RequestTemplate]) -> list[RequestTemplate]:
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    unique: list[RequestTemplate] = []
    for item in items:
        parts = urlsplit(item.url)
        key = (
            item.method,
            parts.netloc,
            parts.path,
            tuple(sorted(item.names)),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
        if len(unique) >= MAX_ENDPOINTS:
            break
    return unique


def nonces_from(html: str, page_url: str) -> list[NonceSource]:
    """Public view of the anti-forgery tokens a page offers."""
    return _nonces_from(html, page_url)


def merge_nonce_values(template: RequestTemplate, tokens: dict[str, str]) -> dict[str, str]:
    """Put resolved tokens into the field map the request will send."""
    values = dict(template.fields)
    for source in template.nonces:
        token = tokens.get(source.name, "")
        if token:
            values[source.name] = token
    return values


def describe(template: RequestTemplate) -> str:
    """Short human-readable line used in prompts."""
    fields = ", ".join(sorted(template.names)) or "-"
    return (
        f"[{template.origin}] {template.method} {template.url} fields={fields}"
        f" nonces={[item.name for item in template.nonces]}"
    )


def as_json(templates: list[RequestTemplate]) -> str:
    return json.dumps([item.to_dict() for item in templates], ensure_ascii=False)
