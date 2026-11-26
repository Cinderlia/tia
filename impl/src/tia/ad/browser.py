"""Browser-side execution confirmation.

This mirrors the trigger check used by dbfuzz (Spider-Scents, USENIX Security 2024):
the payload carries a JavaScript beacon (``xss("tag")``) and a small bootstrap script,
installed before any page script runs, collects beacon calls in ``window.__tia_xss``.
After the page has loaded we read that array and also record ``dialog`` events, which
catches the classic ``alert(1)`` payloads. Execution is evidence, not a verdict: the
callers still decide what an ``executed`` result means.

The browser is optional. ``tia-agent browser-install`` downloads Chrome for Testing;
``TIA_CHROME`` points at a locally installed browser instead. When neither is present
the executor reports ``BROWSER_UNAVAILABLE`` and callers fall back to static analysis.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any

from tia.ad.login import LoginResult
from tia.inf import browser_setup
from tia.inf.accounts import Account

#: Installed before every document so that payloads can call ``xss("tag")``.
BEACON_SCRIPT = """
window.__tia_xss = [];
window.xss = function (value) { window.__tia_xss.push(String(value)); };
"""

#: Builds and submits a POST form on the already loaded page, then navigates.
_SUBMIT_FORM = """
(spec) => {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = spec.action || window.location.href;
  for (const [name, value] of Object.entries(spec.fields || {})) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }
  document.body.appendChild(form);
  form.submit();
}
"""

_MAX_SIGNALS = 20
_MAX_BEACONS = 50


class BrowserUnavailable(RuntimeError):
    """Raised when Playwright or a Chrome binary is missing."""


@dataclass
class ExecutionResult:
    executed: bool
    beacons: list[str] = field(default_factory=list)
    dialogs: list[dict[str, str]] = field(default_factory=list)
    console: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    final_url: str = ""
    duration_ms: int = 0
    screenshot_sha256: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed": self.executed,
            "beacons": self.beacons,
            "dialogs": self.dialogs,
            "console": self.console,
            "page_errors": self.page_errors,
            "final_url": self.final_url,
            "duration_ms": self.duration_ms,
            "screenshot_sha256": self.screenshot_sha256,
            "error": self.error,
        }


def _headless() -> bool:
    """Headless unless the operator explicitly asks for a visible window."""
    if os.environ.get("TIA_BROWSER_HEADED", "") == "1":
        # A GUI environment is required for a headed run; without DISPLAY fall back.
        return not bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


class BrowserExecutor:
    """Run one page in Chrome and report whether the beacon fired."""

    def __init__(
        self,
        *,
        chrome: str | None = None,
        timeout_ms: int = 15_000,
        wait_ms: int = 600,
        headless: bool | None = None,
    ) -> None:
        self.chrome = chrome or os.environ.get("TIA_CHROME", "").strip() or None
        self.timeout_ms = timeout_ms
        self.wait_ms = wait_ms
        self.headless = _headless() if headless is None else headless

    def _binary(self) -> str:
        binary = self.chrome or browser_setup.chrome_binary()
        if binary is None:
            raise BrowserUnavailable(
                "no Chrome found; run `tia-agent browser-install` or set TIA_CHROME"
            )
        return str(binary)

    async def run(
        self,
        url: str,
        *,
        cookies: dict[str, str] | None = None,
        method: str = "GET",
        fields: dict[str, str] | None = None,
        action: str | None = None,
    ) -> ExecutionResult:
        started = time.monotonic()
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - optional dependency
            return ExecutionResult(
                executed=False, error=f"BROWSER_UNAVAILABLE: {exc}"
            )

        binary = self._binary()
        beacons: list[str] = []
        dialogs: list[dict[str, str]] = []
        console: list[str] = []
        page_errors: list[str] = []
        final_url = url
        screenshot_sha256: str | None = None

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    executable_path=binary,
                    headless=self.headless,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
                try:
                    context = await browser.new_context()
                    if cookies:
                        await context.add_cookies(
                            [{"name": name, "value": value, "url": url} for name, value in cookies.items()]
                        )
                    page = await context.new_page()
                    await page.add_init_script(BEACON_SCRIPT)

                    async def on_dialog(dialog: Any) -> None:
                        if len(dialogs) < _MAX_SIGNALS:
                            dialogs.append({"type": dialog.type, "message": dialog.message})
                        await dialog.dismiss()

                    page.on("dialog", on_dialog)
                    page.on("console", lambda msg: console.append(f"{msg.type}: {msg.text}") if len(console) < _MAX_SIGNALS else None)
                    page.on("pageerror", lambda exc: page_errors.append(str(exc)) if len(page_errors) < _MAX_SIGNALS else None)

                    await page.goto(url, wait_until="load", timeout=self.timeout_ms)
                    if method.upper() == "POST" and fields:
                        await page.evaluate(
                            _SUBMIT_FORM, {"action": action or url, "fields": fields}
                        )
                        with contextlib.suppress(Exception):
                            await page.wait_for_load_state("load", timeout=self.timeout_ms)
                    await page.wait_for_timeout(self.wait_ms)
                    final_url = page.url
                    raw = await page.evaluate("() => window.__tia_xss || []")
                    if isinstance(raw, list):
                        beacons = [str(item) for item in raw[:_MAX_BEACONS]]
                    try:
                        shot = await page.screenshot(type="png")
                        screenshot_sha256 = hashlib.sha256(shot).hexdigest()
                    except Exception:  # noqa: BLE001 - screenshots are best effort
                        screenshot_sha256 = None
                finally:
                    await browser.close()
        except BrowserUnavailable as exc:
            return ExecutionResult(executed=False, error=f"BROWSER_UNAVAILABLE: {exc}")
        except Exception as exc:  # noqa: BLE001 - a broken page is not a crash
            return ExecutionResult(
                executed=False,
                beacons=beacons,
                dialogs=dialogs,
                console=console,
                page_errors=page_errors,
                final_url=final_url,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"BROWSER_ERROR: {exc}",
            )

        return ExecutionResult(
            executed=bool(beacons or dialogs),
            beacons=beacons,
            dialogs=dialogs,
            console=console,
            page_errors=page_errors,
            final_url=final_url,
            duration_ms=int((time.monotonic() - started) * 1000),
            screenshot_sha256=screenshot_sha256,
            error=None,
        )


async def browser_login(
    account: Account,
    *,
    timeout_ms: int = 30_000,
    chrome: str | None = None,
) -> LoginResult:
    """Log in through a real browser and return the resulting cookie jar.

    Used when the HTTP login failed several times (JavaScript challenges, WAF,
    client-side CSRF handling). The result is a ``LoginResult`` so callers can
    treat both paths identically; ``via`` is ``"browser"``.
    """

    from tia.ad.login import LoginResult

    empty = LoginResult(ok=False, reason="BROWSER_UNAVAILABLE", via="browser")
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - optional dependency
        empty.reason = f"BROWSER_UNAVAILABLE: {exc}"
        return empty

    try:
        binary = chrome or browser_setup.chrome_binary()
    except browser_setup.BrowserSetupError as exc:
        empty.reason = f"BROWSER_UNAVAILABLE: {exc}"
        return empty
    if binary is None:
        return empty

    headless = _headless()
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                executable_path=str(binary),
                headless=headless,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            try:
                context = await browser.new_context()
                page = await context.new_page()
                await page.goto(account.login_url, wait_until="load", timeout=timeout_ms)

                password = page.locator('input[type="password"]:visible')
                if await password.count() == 0:
                    return LoginResult(
                        ok=False,
                        final_url=page.url,
                        reason="NO_LOGIN_FORM",
                        via="browser",
                    )
                username = page.locator(
                    'input[type="text"]:visible, input[type="email"]:visible,'
                    ' input:not([type]):visible'
                ).first
                if await username.count() == 0:
                    return LoginResult(
                        ok=False,
                        final_url=page.url,
                        reason="NO_USERNAME_FIELD",
                        via="browser",
                    )
                await username.fill(account.username)
                await password.first.fill(account.password)

                submit = page.locator(
                    'button[type="submit"]:visible, input[type="submit"]:visible,'
                    ' button:visible'
                ).first
                clicked = False
                if await submit.count() > 0:
                    try:
                        await submit.click(timeout=5_000)
                        clicked = True
                    except Exception:  # noqa: BLE001 - fall back to Enter
                        clicked = False
                if not clicked or page.url == account.login_url:
                    # The click did nothing (or only re-rendered the form): submit by keyboard.
                    await password.first.press("Enter")
                with contextlib.suppress(Exception):
                    await page.wait_for_load_state("load", timeout=timeout_ms)
                await page.wait_for_timeout(1_000)

                body = await page.content()
                still_login = await page.locator('input[type="password"]').count() > 0
                ok = "logout" in body.lower() or not still_login
                cookies = {
                    item["name"]: item["value"] for item in await context.cookies()
                }
                return LoginResult(
                    ok=ok,
                    status=0,
                    final_url=page.url,
                    reason="LOGGED_IN" if ok else "LOGIN_REJECTED",
                    cookies=cookies,
                    form_action=account.login_url,
                    fields=[],
                    via="browser",
                )
            finally:
                await browser.close()
    except Exception as exc:  # noqa: BLE001 - a broken page is not a crash
        return LoginResult(ok=False, reason=f"BROWSER_ERROR: {exc}", via="browser")
