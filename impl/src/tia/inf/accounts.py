"""Account file: one entry per known login, with roles and a short description.

Passwords never live in the repository: an entry either names an environment
variable (``password_ref: env:NAME``) or a file, and the plain value is read at
login time only. The description is what the planner reads when it has to pick
the least-privileged account that can still reach a page.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import yaml


class AccountsConfigError(ValueError):
    """The account file is missing or malformed."""


@dataclass(frozen=True, slots=True)
class Account:
    """One login the agent may use, with the privilege information it needs."""

    label: str
    base_url: str
    login_url: str
    username: str
    password: str
    roles: tuple[str, ...] = ()
    description: str = ""

    @property
    def url_prefix(self) -> str:
        return self.base_url.rstrip("/") + "/"

    def public(self) -> dict[str, Any]:
        """Show the entry to a model: no secret, only the identity and roles."""

        return {
            "label": self.label,
            "base_url": self.base_url,
            "login_url": self.login_url,
            "username": self.username,
            "roles": list(self.roles),
            "description": self.description,
        }


def _secret(raw: Any, label: str) -> str:
    if isinstance(raw, str) and raw.startswith("env:"):
        name = raw[4:].strip()
        value = os.environ.get(name, "")
        if not value:
            raise AccountsConfigError(f"account {label!r}: environment variable {name!r} is empty")
        return value
    if isinstance(raw, str) and raw.startswith("file:"):
        path = Path(raw[5:].strip()).expanduser()
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AccountsConfigError(
                f"account {label!r}: cannot read password file {path}: {exc}"
            ) from exc
    if isinstance(raw, str) and raw:
        return raw
    raise AccountsConfigError(f"account {label!r}: password or password_ref is required")


def _parse_entry(raw: dict[str, Any], index: int) -> Account:
    label = str(raw.get("label") or "").strip()
    if not label:
        raise AccountsConfigError(f"account #{index}: label is required")
    base_url = str(raw.get("base_url") or "").strip().rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        raise AccountsConfigError(f"account {label!r}: base_url must be an absolute http(s) URL")
    login_url = str(raw.get("login_url") or "").strip()
    if not login_url:
        login_url = urljoin(base_url + "/", "login.php")
    elif login_url.startswith("/"):
        login_url = urljoin(base_url, login_url)
    username = str(raw.get("username") or "").strip()
    if not username:
        raise AccountsConfigError(f"account {label!r}: username is required")
    secret = raw.get("password_ref") if raw.get("password_ref") else raw.get("password")
    roles = raw.get("roles") or []
    if not isinstance(roles, list):
        raise AccountsConfigError(f"account {label!r}: roles must be a list")
    return Account(
        label=label,
        base_url=base_url,
        login_url=login_url,
        username=username,
        password=_secret(secret, label),
        roles=tuple(map(str, roles)),
        description=str(raw.get("description") or ""),
    )


def load_accounts(path: Path) -> list[Account]:
    """Load and validate the account file; an empty file yields no accounts."""

    if not path.is_file():
        raise AccountsConfigError(f"account file not found: {path}")
    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AccountsConfigError(f"account file is not valid YAML: {exc}") from exc
    entries = data.get("accounts") if isinstance(data, dict) else data
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise AccountsConfigError("account file must contain a list of accounts")
    accounts = [
        _parse_entry(entry, index)
        for index, entry in enumerate(entries)
        if isinstance(entry, dict)
    ]
    labels = [account.label for account in accounts]
    if len(set(labels)) != len(labels):
        raise AccountsConfigError("account labels must be unique")
    return accounts


def pick_account(
    accounts: list[Account],
    required_roles: list[str] | tuple[str, ...] = (),
    base_url: str = "",
    label: str = "",
) -> Account | None:
    """Pick the least-privileged account that satisfies the request.

    ``label`` wins when given; otherwise accounts are filtered by URL prefix and
    role coverage, then ordered by privilege breadth (fewer roles first) and by
    label so the choice is deterministic.
    """

    if label:
        for account in accounts:
            if account.label == label:
                return account
        return None
    wanted = {role.lower() for role in required_roles}
    candidates = [
        account
        for account in accounts
        if (not base_url or account.url_prefix.startswith(base_url.rstrip("/") + "/"))
        and wanted <= {role.lower() for role in account.roles}
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda account: (len(account.roles), account.label))
    return candidates[0]


def public_catalog(path: Path | None) -> list[dict[str, Any]]:
    """The identities an agent may switch to, safe to show to a model.

    A missing or malformed account file yields an empty catalog instead of an
    error: switching identity is an option, never a precondition.
    """

    if path is None:
        return []
    try:
        return [account.public() for account in load_accounts(path)]
    except AccountsConfigError:
        return []
