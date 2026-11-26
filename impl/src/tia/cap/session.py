"""Session control: bind a named account and reuse its cookies.

Passwords stay in ``accounts.yaml`` (or an environment reference); this module
only ever returns the public account fields and the resulting session id.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.ad.login import login
from tia.cap.registry import ToolOutput
from tia.inf.accounts import Account, AccountsConfigError, load_accounts, pick_account
from tia.inf.runtime import get_runtime
from tia.schemas.envelope import ErrorCode, ToolError


class SessionBindInput(BaseModel):
    """Either bind one account (label/roles) or list the configured accounts."""

    model_config = ConfigDict(extra="forbid")

    account_label: str = ""
    roles: list[str] = Field(default_factory=list)
    base_url: str = ""
    case_id: str | None = None


def _validate(arguments: dict[str, Any]) -> SessionBindInput:
    try:
        return SessionBindInput.model_validate(arguments)
    except ValidationError as exc:
        raise ToolError(
            ErrorCode.BAD_ARGS,
            f"invalid session_bind arguments: {exc.errors()[0].get('msg', 'bad value')}",
            hint="expected {account_label?: str, roles?: list[str], base_url?: str, case_id?: str}",
        ) from exc


def _accounts() -> list[Account]:
    runtime = get_runtime()
    try:
        return load_accounts(runtime.settings.accounts_path)
    except AccountsConfigError as exc:
        raise ToolError(
            ErrorCode.ENV_ERROR,
            str(exc),
            hint="set TIA_ACCOUNTS to a readable accounts.yaml",
        ) from exc


def _public_account(account: Account) -> dict[str, Any]:
    return account.public()


def _session_data(session: dict[str, Any], *, reused: bool) -> dict[str, Any]:
    cookies = session.get("cookies") or {}
    return {
        "session_id": str(session.get("id", "")),
        "label": str(session.get("label", "")),
        "base_url": str(session.get("base_url", "")),
        "username": str(session.get("username", "")),
        "roles": list(session.get("roles") or []),
        "description": str(session.get("description", "")),
        "login_url": str(session.get("login_url", "")),
        "cookie_count": len(cookies),
        "cookie_names": sorted(cookies),
        "reused": reused,
        "observed_at": str(session.get("observed_at", "")),
    }


async def session_bind(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(arguments)
    runtime = get_runtime()
    accounts = _accounts()

    if not params.account_label and not params.roles:
        sessions = runtime.store.list_sessions(params.base_url)
        return ToolOutput(
            data={
                "bound": False,
                "how_to_bind": (
                    "Choose one label from login_targets (description explains its privileges),"
                    " then call session_bind again with account_label set."
                ),
                "login_targets": [
                    {
                        "label": account.label,
                        "login_url": account.login_url,
                        "username": account.username,
                        "roles": list(account.roles),
                        "description": account.description,
                    }
                    for account in accounts
                ],
                "accounts": [_public_account(account) for account in accounts],
                "sessions": [
                    {
                        "session_id": str(row.get("id", "")),
                        "label": str(row.get("label", "")),
                        "base_url": str(row.get("base_url", "")),
                        "username": str(row.get("username", "")),
                        "roles": list(row.get("roles") or []),
                        "valid": bool(row.get("valid")),
                    }
                    for row in sessions
                ],
            },
            warnings=["CATALOG_ONLY"],
        )

    account = pick_account(
        accounts,
        required_roles=params.roles,
        base_url=params.base_url,
        label=params.account_label,
    )
    if account is None:
        return ToolOutput(
            data={
                "bound": False,
                "requested": {"account_label": params.account_label, "roles": params.roles},
                "accounts": [_public_account(item) for item in accounts],
            },
            warnings=["ACCOUNT_NOT_FOUND"],
        )

    existing = runtime.store.find_session(account.label, account.base_url)
    if existing is not None:
        data = _session_data(existing, reused=True)
        data["bound"] = True
        return ToolOutput(data=data)

    result = login(account)
    if not result.ok:
        raise ToolError(
            ErrorCode.SESSION_INVALID,
            f"login failed for {account.label}: {result.reason}",
            hint="check the credentials, the login page URL or the account roles",
        )
    session_id = runtime.store.add_session(
        label=account.label,
        base_url=account.base_url,
        cookies=result.cookies,
        roles=list(account.roles),
        username=account.username,
        description=account.description,
        login_url=account.login_url,
        case_id=params.case_id,
    )
    row = runtime.store.get_session(session_id)
    if row is None:  # pragma: no cover - just written
        raise ToolError(ErrorCode.ENV_ERROR, "session row vanished after insert")
    data = _session_data(row, reused=False)
    data["bound"] = True
    data["login"] = {
        "status": result.status,
        "final_url": result.final_url,
        "reason": result.reason,
        "form_action": result.form_action,
        "fields": result.fields,
    }
    return ToolOutput(data=data)


_LOGIN_REDIRECT_HINTS = ("login", "signin", "sign-in", "auth")


def _optional_accounts() -> list[Account]:
    """Configured accounts, or an empty list when the file is absent."""

    runtime = get_runtime()
    try:
        return load_accounts(runtime.settings.accounts_path)
    except (AccountsConfigError, OSError):
        return []


def default_account_label() -> str:
    """The label pinned for this run (``TIA_ACCOUNT`` / ``--account``)."""

    return str(getattr(get_runtime().settings, "default_account", "") or "")


def account_for_url(url: str, label: str = "") -> Account | None:
    """Pick an account for a URL: explicit label, pinned label, then the first prefix match."""

    accounts = _optional_accounts()
    if not accounts:
        return None
    wanted = label or default_account_label()
    if wanted:
        return next((item for item in accounts if item.label == wanted), None)
    for item in accounts:
        if url.startswith(item.base_url.rstrip("/") + "/") or url == item.base_url.rstrip("/"):
            return item
    return None


def ensure_session(
    url: str, label: str = "", case_id: str | None = None
) -> tuple[dict[str, Any] | None, list[str]]:
    """Reuse a stored session or log the account in; anonymous when no account matches."""

    account = account_for_url(url, label)
    if account is None:
        return None, []
    runtime = get_runtime()
    existing = runtime.store.find_session(account.label, account.base_url)
    if existing is not None and existing.get("valid"):
        return existing, []
    result = login(account)
    if not result.ok:
        return None, [f"AUTO_LOGIN_FAILED: {account.label}: {result.reason}"]
    session_id = runtime.store.add_session(
        label=account.label,
        base_url=account.base_url,
        cookies=result.cookies,
        roles=list(account.roles),
        username=account.username,
        description=account.description,
        login_url=account.login_url,
        case_id=case_id,
    )
    return runtime.store.get_session(session_id), []


def resolve_session(
    session_id: str | None, url: str, label: str = ""
) -> tuple[str | None, dict[str, str], list[str]]:
    """Cookies for a request: explicit session, else an automatically maintained one."""

    if session_id:
        return session_id, session_cookies(session_id), []
    row, warnings = ensure_session(url, label)
    if row is None:
        return None, {}, warnings
    return str(row["id"]), dict(row.get("cookies") or {}), warnings


def session_cookies(session_id: str) -> dict[str, str]:
    """Cookies of a bound session; SESSION_INVALID when the id is unknown."""

    runtime = get_runtime()
    session = runtime.store.get_session(session_id)
    if session is None or not session.get("valid"):
        raise ToolError(
            ErrorCode.SESSION_INVALID,
            f"unknown or expired session: {session_id}",
            hint="call session_bind first",
        )
    return dict(session.get("cookies") or {})


def looks_like_login(status: int, location: str, body: str) -> bool:
    """Cheap heuristic: a redirect to a login page or a page that only offers a login form."""

    lowered = (location or "").lower()
    if status in {301, 302, 303, 307, 308} and any(hint in lowered for hint in _LOGIN_REDIRECT_HINTS):
        return True
    if "logout" in body.lower():
        return False
    return re.search(r"""type\s*=\s*["']?password""", body, re.IGNORECASE) is not None


def renew_session(session_id: str) -> tuple[str, dict[str, str]]:
    """Log the same account in again and replace the stored session.

    Returns the new session id and cookies; raises SESSION_INVALID when the
    account is no longer configured or the login fails again.
    """

    runtime = get_runtime()
    previous = runtime.store.get_session(session_id)
    if previous is None:
        raise ToolError(
            ErrorCode.SESSION_INVALID,
            f"unknown session: {session_id}",
            hint="call session_bind first",
        )
    label = str(previous.get("label") or "")
    account = next((item for item in _accounts() if item.label == label), None)
    if account is None:
        raise ToolError(
            ErrorCode.SESSION_INVALID,
            f"account {label!r} is no longer configured",
            hint="re-add it to accounts.yaml and call session_bind",
        )
    result = login(account)
    if not result.ok:
        raise ToolError(
            ErrorCode.SESSION_INVALID,
            f"session renewal failed for {label}: {result.reason}",
            hint="the credentials may have changed or the login page moved",
        )
    runtime.store.invalidate_session(session_id)
    new_id = runtime.store.add_session(
        label=account.label,
        base_url=account.base_url,
        cookies=result.cookies,
        roles=list(account.roles),
        username=account.username,
        description=account.description,
        login_url=account.login_url,
        case_id=str(previous.get("case_id") or "") or None,
    )
    return new_id, result.cookies
