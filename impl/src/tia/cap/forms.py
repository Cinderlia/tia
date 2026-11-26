"""Form discovery shared by the delivery agents.

The inject agent and the direct agent both need "where do I submit, which
field carries my parameter, and what constraints does the page advertise".
Keeping one implementation here means a page quirk is fixed once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from tia.cap.domscan import Document


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""
    maxlength: int | None = None
    required: bool = False


@dataclass
class PageForm:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"
    files: list[str] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        return [item.name for item in self.fields]


def _int_attr(attrs: dict[str, str], key: str) -> int | None:
    raw = attrs.get(key)
    if raw is None or not raw.strip().isdigit():
        return None
    return int(raw)


def forms_from_document(document: Document, page_url: str) -> list[PageForm]:
    """Every form in document order, with field constraints."""
    forms: list[PageForm] = []
    for node in document.nodes:
        if node.tag != "form":
            continue
        action = node.attrs.get("action", "")
        method = (node.attrs.get("method") or "get").lower()
        enctype = node.attrs.get("enctype", "application/x-www-form-urlencoded")
        fields: list[FormField] = []
        files: list[str] = []
        stack = list(node.children)
        while stack:
            child = stack.pop()
            if child.tag not in {"input", "textarea", "select", "button"}:
                stack.extend(child.children)
                continue
            name = child.attrs.get("name")
            kind = (child.attrs.get("type") or "text").lower()
            if name and kind == "file":
                files.append(name)
            elif name and kind not in {"image", "reset"}:
                fields.append(
                    FormField(
                        name=name,
                        type=kind,
                        value=child.attrs.get("value", ""),
                        maxlength=_int_attr(child.attrs, "maxlength"),
                        required="required" in child.attrs,
                    )
                )
            stack.extend(child.children)
        fields.sort(key=lambda item: item.name)
        forms.append(
            PageForm(
                action=urljoin(page_url, action or page_url),
                method=method,
                fields=fields,
                enctype=enctype,
                files=files,
            )
        )
    return forms


def forms_from_formparse(forms: list[dict[str, Any]], page_url: str) -> list[PageForm]:
    """Adapt the ``form_parse`` tool output (rich constraints) to PageForm."""
    adapted: list[PageForm] = []
    for item in forms:
        fields = [
            FormField(
                name=str(field.get("name") or ""),
                type=str(field.get("type") or "text"),
                value=str(field.get("value") or ""),
                maxlength=field.get("maxlength") if isinstance(field.get("maxlength"), int) else None,
                required=bool(field.get("required")),
            )
            for field in item.get("fields") or []
            if field.get("name")
        ]
        action = str(item.get("action") or "")
        adapted.append(
            PageForm(
                action=urljoin(page_url, action) if action else page_url,
                method=str(item.get("method") or "get").lower(),
                fields=fields,
                enctype=str(item.get("enctype") or "application/x-www-form-urlencoded"),
            )
        )
    return adapted


def merge_forms(primary: list[PageForm], constraints: list[PageForm]) -> list[PageForm]:
    """Merge delivery fields (document parse, keeps submit buttons) with
    constraint data (``form_parse`` tool, maxlength/required)."""
    merged: list[PageForm] = []
    for index, form in enumerate(primary):
        extra = constraints[index] if index < len(constraints) else None
        by_name = {field.name: field for field in (extra.fields if extra else [])}
        fields: list[FormField] = []
        for item in form.fields:
            richer = by_name.get(item.name)
            if richer is not None:
                item.maxlength = richer.maxlength if richer.maxlength is not None else item.maxlength
                item.required = item.required or richer.required
            fields.append(item)
        for name, extra_field in by_name.items():
            if name not in {item.name for item in fields}:
                fields.append(extra_field)
        merged.append(
            PageForm(
                action=form.action,
                method=form.method,
                fields=fields,
                enctype=form.enctype,
            )
        )
    return merged


def find_form(forms: list[PageForm], param: str, *, method: str | None = None) -> PageForm | None:
    """Prefer the form that carries ``param``; fall back to the first POST form."""
    candidates = [item for item in forms if method is None or item.method == method]
    if param:
        for form in candidates:
            if param in form.names:
                return form
    if method == "post":
        for form in candidates:
            if form.method == "post":
                return form
    return candidates[0] if candidates else None
