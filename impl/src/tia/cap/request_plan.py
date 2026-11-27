"""Let the model plan a request that reaches a specific code path.

Local rules can validate a request but they cannot know what a page needs to
enter a branch: required siblings, mutually exclusive fields, hidden flags.
That planning is the agent's job. This module asks the model for one concrete
request (URL, method, field values), validates it against the forms the page
actually exposes, and returns it. Execution decides whether the plan worked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from tia.ad.llm import LlmClient
from tia.cap.forms import PageForm

MAX_FIELDS = 40
MAX_SOURCE = 4000


@dataclass
class PlannedRequest:
    url: str
    method: str
    values: dict[str, str] = field(default_factory=dict)
    payload_field: str = ""
    files: dict[str, str] = field(default_factory=dict)
    source: str = "llm"
    reason: str = ""
    rejection: str = ""
    warnings: list[str] = field(default_factory=list)
    payload: str = ""
    column: str = ""
    account: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "model": self.values,
            "payload_field": self.payload_field,
            "files": self.files,
            "source": self.source,
            "reason": self.reason,
            "rejection": self.rejection,
            "warnings": self.warnings,
            "payload": self.payload,
            "column": self.column,
            "account": self.account,
        }


_SYSTEM = (
    "You plan HTTP requests for a web security agent. Reply with one JSON object only. "
    "Prefer field names from the given forms; if the source shows a field that the "
    "markup does not list (a JS-built field, a submit button, a token), name it anyway "
    "and say why in reason. Strings only, at most "
    f"{MAX_FIELDS} fields. Always include \"payload\": the exact string you place in that "
    "field; it must contain the TAG verbatim and be shaped for the sink context. "
    "If a file input is required to enter the branch, name it in payload_field_file."
)


def _prompt(
    *,
    goal: str,
    page_url: str,
    forms: list[PageForm],
    source_text: str,
    payload: str,
    hint: str,
    observation: str = "",
    constraints: str = "",
    html: str = "",
    tag: str = "",
    sink: str = "",
    accounts: list[dict[str, Any]] | None = None,
) -> str:
    shape = []
    for index, item in enumerate(forms):
        shape.append(
            {
                "index": index,
                "action": item.action,
                "method": item.method,
                "enctype": item.enctype,
                "fields": [
                    {
                        "name": entry.name,
                        "type": entry.type,
                        "value": entry.value,
                        "maxlength": entry.maxlength,
                        "required": entry.required,
                    }
                    for entry in item.fields
                ],
                "files": item.files,
            }
        )
    import json

    users = ""
    if accounts:
        rows = [
            {
                "label": item.get("label"),
                "roles": item.get("roles") or [],
                "description": item.get("description") or "",
            }
            for item in accounts
        ]
        users = (
            "SWITCHABLE USERS (from the operator's account file; label + roles + "
            "what the person said it can do). Leave \"account\" empty for the current "
            "user, or name one when the page redirected to a login/denied page and "
            "this identity cannot finish the action:\n"
            f"{json.dumps(rows, ensure_ascii=False)[:2500]}\n"
        )
    return (
        f"GOAL: {goal}\n"
        f"PAGE: {page_url}\n"
        f"{users}"
        f"HINT: {hint}\n"
        f"STORAGE COLUMNS: {constraints[:1200]}\n"
        f"SLICE SINK (build the payload for THIS context, not for any SQL nearby): {sink[:1500]}\n"
        f"LAST ATTEMPT OBSERVATION: {observation[:800]}\n"
        f"TAG: {tag}\n"
        f"PAYLOAD SEED: {payload!r}\n"
        "FORMS:\n"
        f"{json.dumps(shape, ensure_ascii=False)[:6000]}\n"
        "SINK SOURCE:\n"
        f"{source_text[:MAX_SOURCE]}\n"
        "PAGE HTML (trimmed):\n"
        f"{html[:6000]}\n"
        "Return {\"url\", \"method\", \"fields\", \"payload_field\", "
        "\"payload_field_file\", \"payload\", \"column\", \"account\", \"reason\"}. "
        "\"account\" is a label from SWITCHABLE USERS or empty. "
        "\"payload\" must contain the TAG verbatim and be built for the sink context; "
        "\"column\" is the storage column the payload should end up in, if known."
    )


def _same_origin(url: str, page_url: str) -> bool:
    left, right = urlparse(url), urlparse(page_url)
    return (left.scheme, left.netloc) == (right.scheme, right.netloc)


def _clean_fields(raw: Any, allowed: set[str]) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, str] = {}
    for name, value in raw.items():
        key = str(name)
        if key not in allowed or len(cleaned) >= MAX_FIELDS:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            cleaned[key] = "" if value is None else str(value)
    return cleaned


async def plan_request(
    *,
    client: LlmClient | None,
    goal: str,
    page_url: str,
    forms: list[PageForm],
    source_text: str,
    payload: str,
    hint: str = "",
    observation: str = "",
    constraints: str = "",
    html: str = "",
    tag: str = "",
    sink: str = "",
    fallback_fields: dict[str, str] | None = None,
    fallback_method: str = "POST",
    accounts: list[dict[str, Any]] | None = None,
) -> PlannedRequest | None:
    """Ask the model for a request plan; validate it; fall back to a local fill."""
    allowed = {entry.name for form in forms for entry in form.fields}
    file_names = {name for form in forms for name in form.files}
    if client is not None:
        reply = await client.complete_json(
            _SYSTEM,
            _prompt(
                goal=goal,
                page_url=page_url,
                forms=forms,
                source_text=source_text,
                payload=payload,
                hint=hint,
                observation=observation,
                constraints=constraints,
                html=html,
                tag=tag,
                accounts=accounts,
            ),
        )
        url = str(reply.get("url") or "")
        method = str(reply.get("method") or "POST").upper()
        payload_field = str(reply.get("payload_field") or "")
        raw_fields = reply.get("fields")
        file_field = str(reply.get("payload_field_file") or "")
        problems: list[str] = []
        warnings: list[str] = []
        if not url:
            problems.append("no url in the plan")
        elif not _same_origin(url, page_url):
            problems.append(f"url {url!r} is not same-origin with the page {page_url!r}")
        if method not in {"GET", "POST"}:
            problems.append(f"method {method!r} is not GET or POST")
        if isinstance(raw_fields, list):
            # Some models answer with a list of field names instead of a mapping;
            # keep the names and fill non-payload fields with a harmless value.
            raw_fields = {
                str(name): "tia" for name in raw_fields if isinstance(name, (str, int))
            }
        if not isinstance(raw_fields, dict) or not raw_fields:
            problems.append("the plan has no fields")
            raw_fields = {}
        if payload_field and payload_field not in raw_fields:
            problems.append(
                f"payload_field {payload_field!r} is not one of the submitted fields"
            )
        unknown = sorted(str(name) for name in raw_fields if str(name) not in allowed | file_names)
        if unknown:
            warnings.append(
                f"fields {unknown} are not present in the parsed form "
                f"(known fields: {sorted(allowed)}); the request is sent anyway"
            )
        limits = {entry.name: entry.maxlength for form in forms for entry in form.fields}
        too_long = []
        for name, value in raw_fields.items():
            limit = limits.get(str(name))
            if limit and len(str(value)) > int(limit):
                too_long.append(f"{name} (maxlength {limit}, got {len(str(value))})")
        if too_long:
            warnings.append(f"values exceed maxlength: {too_long}")
        if file_field and file_field not in file_names:
            warnings.append(
                f"file field {file_field!r} is not a parsed file input "
                f"(file inputs: {sorted(file_names)}); the upload is attempted anyway"
            )
        if problems:
            rejection = "; ".join(problems)
            return PlannedRequest(
                url=url,
                method=method,
                values={},
                payload_field="",
                files={},
                source="rejected",
                reason="the local validator rejected an unsafe or unusable plan",
                rejection=rejection,
            )
        planned_payload = str(reply.get("payload") or "").strip() or payload
        if tag and tag not in planned_payload:
            warnings.append(
                f"the planned payload {planned_payload!r} does not contain the tag {tag!r}; "
                f"using the seed payload instead"
            )
            planned_payload = payload
        planned_column = str(reply.get("column") or "").strip()
        known_columns = {
            part.split(":", 1)[0].strip()
            for part in constraints.split(",")
            if ":" in part
        }
        if planned_column and known_columns and planned_column not in known_columns:
            warnings.append(
                f"column {planned_column!r} is not in the storage columns "
                f"{sorted(known_columns)}; the local choice is kept"
            )
            planned_column = ""
        values = {
            str(name): "" if value is None else str(value)
            for name, value in raw_fields.items()
            if len(str(name)) <= 64
        }
        if payload_field in values:
            values[payload_field] = planned_payload
        files: dict[str, str] = {}
        if file_field:
            files[file_field] = "tia-upload.png"
        chosen_account = str(reply.get("account") or "").strip()
        if chosen_account:
            labels = {str(item.get("label") or "") for item in accounts or []}
            if chosen_account not in labels:
                warnings.append(
                    f"account {chosen_account!r} is not one of {sorted(labels)}; "
                    f"the current user is kept"
                )
                chosen_account = ""
        return PlannedRequest(
            url=url,
            method=method,
            values=values,
            payload_field=payload_field,
            files=files,
            source="llm",
            reason=str(reply.get("reason") or "")[:300],
            warnings=warnings,
            payload=planned_payload,
            column=planned_column,
            account=chosen_account,
        )
    if fallback_fields is None:
        return None
    values = dict(fallback_fields)
    return PlannedRequest(
        url=page_url,
        method=fallback_method,
        values=values,
        payload_field="",
        files={},
        source="local",
        reason="model unavailable or unusable; filled every form field",
    )
