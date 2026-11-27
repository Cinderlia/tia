"""Blind SQL injection: accept only after a behavioural differential.

The probe already tells us whether a payload entered an executed statement; that
is the diagnosis step.  When the page shows nothing (blind injection) the class
cannot claim success from the statement alone, so this module sends a
true/false pair (or a delayed request) and compares the responses.  Two gates
must both hold before a blind finding is accepted:

* diagnosis — the probe saw the marker in an executed statement, or the request
  produced a database error (the injection reached the engine);
* differential — the true branch and the false branch (or the delayed read)
  behave differently, so the engine actually evaluated the injected predicate.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from tia.orch.kernel import Kernel, ToolCallError

#: A boolean pair must move the response by at least this many bytes, or change
#: its status/error text; anything smaller is treated as page noise.
BLIND_BOOLEAN_DELTA = 8
#: A time payload asks the engine for BLIND_DELAY_S; we accept half of it because
#: the HTTP round trip and page rendering add their own few milliseconds.
BLIND_DELAY_S = 2.0
BLIND_TIME_DELTA_MS = 1100.0


@dataclass
class BlindResult:
    kind: str = ""
    confirmed: bool = False
    diagnosis: bool = False
    detail: dict[str, Any] = field(default_factory=dict)


def _arguments(url: str, method: str, values: dict[str, str]) -> dict[str, Any]:
    arguments: dict[str, Any] = {"url": url, "method": method.upper()}
    if method.upper() == "POST":
        arguments["body"] = urlencode(values)
        arguments["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        arguments["params"] = values
    return arguments


async def _send(
    kernel: Kernel,
    case_id: str,
    url: str,
    method: str,
    values: dict[str, str],
) -> dict[str, Any]:
    arguments = _arguments(url, method, values)
    arguments["case_id"] = case_id
    run: dict[str, Any] = await kernel.call("probe_run", arguments)
    return run


def _response(run: dict[str, Any]) -> dict[str, Any]:
    http = run.get("http") or {}
    queries = run.get("queries") or []
    statements = [str(item.get("sql") or "") for item in queries if isinstance(item, dict)]
    return {
        "status": int(http.get("status") or 0),
        "bytes": int(http.get("bytes") or 0),
        "elapsed_ms": float(http.get("elapsed_ms") or 0.0),
        "error": str(run.get("error") or ""),
        "statements": statements,
    }


def _diagnosis(responses: list[dict[str, Any]], tag: str) -> bool:
    for response in responses:
        if any(tag in statement for statement in response["statements"]):
            return True
        if response["error"]:
            return True
    return False


async def blind_check(
    kernel: Kernel,
    *,
    case_id: str,
    file: str,
    line: int,
    url: str,
    method: str,
    field: str,
    base_values: dict[str, str],
    pairs: list[tuple[str, str, str]],
    tag: str,
) -> BlindResult:
    """Try the class's blind pairs; the first confirmed one wins.

    Each pair is self-contained: the true branch and its false (or undelayed)
    control are compared against each other, so no separate baseline request is
    needed.  A pair only counts when the probe saw the marker (or the page
    produced a database error) *and* the two branches behave differently.
    """
    result = BlindResult()
    if not field or not file or not line or not pairs:
        return result
    armed = False
    try:
        await kernel.call(
            "probe_arm",
            {
                "case_id": case_id,
                "file": file,
                "line": line,
                "output": f"blind-{tag}.json",
            },
        )
        armed = True
        for kind, true_payload, false_payload in pairs:
            try:
                truthy = _response(
                    await _send(
                        kernel, case_id, url, method, {**base_values, field: true_payload}
                    )
                )
                falsy = _response(
                    await _send(
                        kernel, case_id, url, method, {**base_values, field: false_payload}
                    )
                )
            except ToolCallError as exc:
                result.detail.setdefault("errors", []).append(exc.code.value)
                continue
            diagnosis = _diagnosis([truthy, falsy], tag)
            if kind == "time":
                delta = truthy["elapsed_ms"] - falsy["elapsed_ms"]
                confirmed = diagnosis and delta >= BLIND_TIME_DELTA_MS
                result.detail["time"] = {
                    "control_ms": falsy["elapsed_ms"],
                    "delayed_ms": truthy["elapsed_ms"],
                    "delta_ms": round(delta, 2),
                    "diagnosis": diagnosis,
                    "confirmed": confirmed,
                    "statements": truthy["statements"][:2],
                }
            else:
                bytes_delta = abs(truthy["bytes"] - falsy["bytes"])
                status_delta = truthy["status"] != falsy["status"]
                error_delta = bool(truthy["error"]) != bool(falsy["error"])
                confirmed = diagnosis and (
                    bytes_delta >= BLIND_BOOLEAN_DELTA or status_delta or error_delta
                )
                result.detail["boolean"] = {
                    "bytes": [truthy["bytes"], falsy["bytes"]],
                    "status": [truthy["status"], falsy["status"]],
                    "bytes_delta": bytes_delta,
                    "diagnosis": diagnosis,
                    "confirmed": confirmed,
                    "true_payload": true_payload,
                    "statements": truthy["statements"][:2],
                }
            if confirmed:
                result.kind = kind
                result.confirmed = True
                result.diagnosis = diagnosis
                return result
    finally:
        if armed:
            with contextlib.suppress(ToolCallError):
                await kernel.call("probe_disarm", {"case_id": case_id})
    return result
