"""HTTP adapter: explicit cookies, no redirect following by default, bounded body.

When following redirects, this adapter manually requests hop-by-hop and records ``redirect_chain`` (H10 requires
"where it ultimately landed", not httpx's implicit behavior).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import httpx

from tia.schemas.envelope import ErrorCode, ToolError


@dataclass(slots=True)
class HttpResult:
    status: int
    final_url: str
    content_type: str
    headers: dict[str, str]
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    body_bytes: int = 0
    body: str = ""
    truncated: bool = False
    elapsed_ms: float = 0.0


def merge_query(url: str, params: dict[str, Any] | None) -> str:
    """Attach request parameters without dropping the query already in ``url``.

    ``httpx`` treats ``params`` as the whole query string of the request, which
    silently discards an action such as ``?action=set_flag`` when the caller also
    passes the action's fields separately. Merging here keeps both.
    """

    if not params:
        return url
    parts = urlsplit(url)
    pairs = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)]
    overridden = {str(key) for key in params}
    pairs = [(key, value) for key, value in pairs if key not in overridden]
    pairs.extend((str(key), str(value)) for key, value in params.items())
    query = "&".join(f"{key}={value}" for key, value in pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


class HttpClient:
    def __init__(self, *, timeout: float = 30.0) -> None:
        self.timeout = timeout

    def fetch(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
        max_redirects: int = 5,
        max_bytes: int = 32 * 1024,
        marker: str | None = None,
        around: int = 800,
        files: dict[str, tuple[str, bytes]] | None = None,
    ) -> HttpResult:
        chain: list[dict[str, Any]] = []
        started = time.perf_counter()
        current = url
        request_headers = dict(headers or {})
        request_headers.setdefault("User-Agent", "tia-agent/0.1")
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                cookies=cookies or {},
            ) as client:
                for _ in range(max_redirects + 1):
                    target = merge_query(current, params)
                    if files:
                        form_data = dict(parse_qsl(body or ""))
                        response = client.request(
                            method,
                            target,
                            data=form_data or None,
                            files=files,
                            headers={
                                key: value
                                for key, value in request_headers.items()
                                if key.lower() != "content-type"
                            },
                        )
                    else:
                        response = client.request(
                            method,
                            target,
                            content=body.encode() if body is not None else None,
                            headers=request_headers,
                        )
                    if response.is_redirect and follow_redirects:
                        location = response.headers.get("location", "")
                        chain.append({"status": response.status_code, "location": location})
                        current = urljoin(current, location)
                        method = "GET"
                        params = None
                        body = None
                        continue
                    raw = response.content
                    text = raw.decode(response.encoding or "utf-8", errors="replace")
                    return HttpResult(
                        status=response.status_code,
                        final_url=str(response.url),
                        content_type=response.headers.get("content-type", ""),
                        headers={k.lower(): v for k, v in response.headers.items()},
                        redirect_chain=chain,
                        body_bytes=len(raw),
                        body=_window(text, marker, around, max_bytes),
                        truncated=len(text.encode()) > max_bytes,
                        elapsed_ms=round((time.perf_counter() - started) * 1000.0, 2),
                    )
        except httpx.HTTPError as exc:
            raise ToolError(
                ErrorCode.ENV_ERROR,
                f"HTTP request failed: {type(exc).__name__}: {exc}",
                retryable=True,
                hint="Verify target service is reachable (use 127.0.0.1 inside container)",
            ) from exc
        raise ToolError(
            ErrorCode.RATE_LIMITED,
            f"Exceeded {max_redirects} redirects",
            hint="Check login redirect or base_url correctness",
        )


def _window(text: str, marker: str | None, around: int, max_bytes: int) -> str:
    encoded = text.encode()
    if len(encoded) <= max_bytes:
        return text
    if marker:
        pos = text.find(marker)
        if pos >= 0:
            start = max(0, pos - around)
            end = min(len(text), pos + len(marker) + around)
            return text[start:end]
    return encoded[:max_bytes].decode("utf-8", errors="ignore")
