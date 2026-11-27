"""HTTP login: discover the login form, submit it, keep the cookies.

The form heuristic follows YuraScanner's login module (a form that contains a
password field and a small number of visible inputs), but the submission is a
plain HTTP request so the resulting cookies can be handed to the probe, verify
and trace tools unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from tia.cap.domscan import parse
from tia.cap.forms import PageForm, forms_from_document
from tia.inf.accounts import Account

_MAX_VISIBLE_FIELDS = 10


@dataclass(slots=True)
class LoginResult:
    """Outcome of one login attempt; secret values never appear here."""

    ok: bool
    status: int = 0
    final_url: str = ""
    reason: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    form_action: str = ""
    fields: list[str] = field(default_factory=list)
    via: str = "http"


def pick_login_form(forms: list[PageForm]) -> PageForm | None:
    """The smallest form that carries a password field, as YuraScanner does."""

    best: PageForm | None = None
    for form in forms:
        if not any((item.type or "").lower() == "password" for item in form.fields):
            continue
        visible = sum(1 for item in form.fields if (item.type or "").lower() != "hidden")
        if visible > _MAX_VISIBLE_FIELDS:
            continue
        if best is None or len(form.fields) < len(best.fields):
            best = form
    return best


def _submit_values(form: PageForm, username: str, password: str) -> dict[str, str]:
    values: dict[str, str] = {}
    username_filled = False
    for item in form.fields:
        kind = (item.type or "text").lower()
        name = item.name
        if not name or kind in {"button", "reset", "image", "file"}:
            continue
        if kind == "submit":
            # A real click submits the button's name/value; several apps gate on it.
            values[name] = item.value or ""
        elif kind == "password":
            values[name] = password
        elif kind in {"text", "email"} and not username_filled:
            values[name] = username
            username_filled = True
        elif kind in {"checkbox", "radio"}:
            if item.value:
                values[name] = item.value
        else:
            values[name] = item.value or ""
    return values


def _login_page_is_over(body: str, url: str) -> bool:
    """A page without a password form (or with a logout link) means login ended."""

    if "logout" in body.lower():
        return True
    forms = forms_from_document(parse(body), url)
    return pick_login_form(forms) is None


def login(
    account: Account,
    *,
    timeout: float = 20.0,
    max_redirects: int = 4,
) -> LoginResult:
    """Log in over HTTP and return the cookie jar; never raises on bad credentials."""

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "tia-agent/0.1"},
        ) as client:
            page = client.get(account.login_url)
            hops = 0
            while page.is_redirect and hops < max_redirects:
                location = page.headers.get("location", "")
                if not location:
                    break
                target = urljoin(str(page.url), location)
                hops += 1
                page = client.get(target)
                if target == account.login_url:
                    break
            if page.status_code >= 400:
                return LoginResult(
                    False, page.status_code, str(page.url), f"LOGIN_PAGE_STATUS_{page.status_code}"
                )
            form = pick_login_form(forms_from_document(parse(page.text), str(page.url)))
            if form is None:
                return LoginResult(False, page.status_code, str(page.url), "NO_LOGIN_FORM")
            values = _submit_values(form, account.username, account.password)
            action = urljoin(str(page.url), form.action or str(page.url))
            method = (form.method or "POST").upper()
            response = client.request(
                method if method in {"GET", "POST"} else "POST",
                action,
                data=None if method == "GET" else values,
                params=values if method == "GET" else None,
            )
            hops = 0
            while response.is_redirect and hops < max_redirects:
                location = response.headers.get("location", "")
                response = client.get(urljoin(str(response.url), location))
                hops += 1
            cookies = {name: value for name, value in client.cookies.items()}
            url = str(response.url)
            if response.status_code >= 400:
                return LoginResult(
                    False, response.status_code, url, f"LOGIN_STATUS_{response.status_code}", cookies
                )
            if _login_page_is_over(response.text, url):
                return LoginResult(
                    True,
                    response.status_code,
                    url,
                    "LOGGED_IN",
                    cookies,
                    action,
                    list(values),
                )
            return LoginResult(
                False,
                response.status_code,
                url,
                "LOGIN_REJECTED",
                cookies,
                action,
                list(values),
            )
    except httpx.HTTPError as exc:
        return LoginResult(False, 0, account.login_url, f"LOGIN_HTTP_ERROR: {exc}")
