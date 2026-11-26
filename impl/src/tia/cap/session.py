"""Session control: bind a named account and reuse its cookies.

Passwords stay in ``accounts.yaml`` (or an environment reference); this module
only ever returns the public account fields and the resulting session id.
"""

from __future__ import annotations

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
