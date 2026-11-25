"""HTTP 适配器：显式 Cookie、默认不跟随重定向、有界 body。

跟随重定向时由本适配器手动逐跳请求并记录 ``redirect_chain``（H10 需要的是
"到底被带到了哪里"，而不是 httpx 的隐式行为）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

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
    ) -> HttpResult:
        chain: list[dict[str, Any]] = []
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
                    response = client.request(
                        method,
                        current,
                        params=params,
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
                    )
        except httpx.HTTPError as exc:
            raise ToolError(
                ErrorCode.ENV_ERROR,
                f"HTTP 请求失败: {type(exc).__name__}: {exc}",
                retryable=True,
                hint="确认目标服务可达（容器内用 127.0.0.1）",
            ) from exc
        raise ToolError(
            ErrorCode.RATE_LIMITED,
            f"超过 {max_redirects} 次重定向",
            hint="检查登录跳转或 base_url 是否正确",
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
