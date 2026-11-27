"""Request-only prover: reach a sink without writing a stored value first.

The XSS path stores a payload and reads it back.  Some sinks (SQL injection,
command injection, path traversal…) need nothing stored: the payload arrives in
the request itself.  The only thing that changes between such classes is the
observation channel, which the sink class owns; this module therefore contains no
vulnerability-specific rule.  It fills the request from the page's own form, sends
bounded payload candidates, and asks the class whether the observation proves the
sink was reached.
"""

from __future__ import annotations

import contextlib
import re
import secrets
from typing import Any
from urllib.parse import urlencode

from tia.cap.blind import blind_check
from tia.cap.domscan import parse
from tia.cap.forms import FormField, PageForm, find_form, forms_from_document
from tia.cap.statement import request_carriers, statement_origin
from tia.dom.trigger import StageRecord, TriggerResult, normalize_slice
from tia.inf.reports import write_case_report
from tia.inf.runtime import get_runtime
from tia.inf.settings import attempt_limit
from tia.orch.kernel import Kernel, LocalToolClient, ToolCallError, ToolClient
from tia.orch.learning import record_case
from tia.sinks.base import Observation, trigger_verdict
from tia.sinks.registry import sink_class_for

#: How many (payload, request-shape) pairs one slice may send.
REQUEST_ATTEMPTS = attempt_limit("request", 6)

_POST_VAR_RE = re.compile(r"\$_(?:POST|GET|REQUEST)\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]")


def _tag() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(4))


def _target_line(raw: dict[str, Any], sink_line: int) -> int:
    """Line the probe should watch: the statement line when the slice names one."""
    probe = raw.get("sqlProbe")
    config = probe.get("extensionConfig") if isinstance(probe, dict) else None
    if isinstance(config, dict):
        with contextlib.suppress(TypeError, ValueError):
            line = int(config.get("line") or 0)
            if line > 0:
                return line
    return int(sink_line or 0)


def _request_shapes(form: PageForm, param: str, payload: str) -> list[dict[str, str]]:
    """Generic request shapes, from the narrowest to the widest.

    Narrow first: a page may have mutually exclusive fields (sending all of them
    can route into an error branch).  Wide second: some pages require their other
    fields to be present.  No field is special-cased.
    """
    shapes: list[dict[str, str]] = [{param: payload}]
    wide: dict[str, str] = {}
    pressed: FormField | None = None
    for field in form.fields:
        kind = (field.type or "text").lower()
        if kind in {"submit", "button", "reset", "image", "file"}:
            # A browser presses exactly one submit control; that control is part
            # of the request (pages often branch on ``isset($_POST['action'])``).
            if pressed is None and kind in {"submit", "button"}:
                pressed = field
            continue
        wide[field.name] = "1" if kind in {"number", "range"} else "tia"
    wide[param] = payload
    if pressed is not None:
        wide[pressed.name] = pressed.value or "1"
    if wide != {param: payload}:
        shapes.append(wide)
    return shapes


async def run_request_prover(
    raw_slice: dict[str, Any],
    *,
    base_url: str,
    payload_base: str = "",
    budget: int = 40,
    client: ToolClient | None = None,
    slice_id: str | None = None,
    flow: dict[str, Any] | None = None,
) -> TriggerResult:
    rt = get_runtime()
    slice_doc = normalize_slice(raw_slice)
    kind = str(slice_doc.get("kind") or "")
    sink_class = sink_class_for(kind)
    sink = slice_doc["sink"]
    sink_file, sink_line = sink["file"], sink["line"]
    params = [str(p) for p in (slice_doc.get("params") or [])]
    stages: list[StageRecord] = []
    notes: dict[str, Any] = {
        "base_url": base_url,
        "sink": f"{sink_file}:{sink_line}",
        "sink_file": sink_file,
        "sink_code": str(sink.get("code") or ""),
        "sink_class": sink_class.name,
    }
    if flow:
        notes["flow_id"] = str(flow.get("flow_id") or "")
        notes["flow_class"] = str(flow.get("sink_class") or "")

    kernel = Kernel(
        profile="trigger",
        budget=budget,
        client=client or LocalToolClient(profile="trigger"),
    )

    def done(result: TriggerResult) -> TriggerResult:
        record_case(rt.store, {"sinkFile": sink_file}, result.verdict, result.notes)
        return result

    # P0 create the case ---------------------------------------------------------
    opened = await kernel.call(
        "case_open", {"slice": slice_doc, "agent": "trigger", "write_targets": []}
    )
    case_id = str(opened["case_id"])
    kernel.case_id = case_id
    kernel.slice_id = slice_id
    stages.append(StageRecord("P0", True, f"case_id={case_id}"))

    if "sql_probe" not in sink_class.channels():
        stages.append(StageRecord("P1", False, f"no request-only channel for {sink_class.name}"))
        return done(
            TriggerResult(
                case_id=case_id,
                verdict="NOT_EXECUTED",
                residue=None,
                report=await kernel.report(),
                stages=stages,
                notes=notes,
                trace=kernel.trace,
            )
        )

    # P1 the probe target is the statement line the slice points at ----------------
    source = await kernel.call(
        "source_read", {"file": sink_file, "around": {"line": sink_line, "n": 40}}
    )
    source_text = "\n".join(str(line["text"]) for line in source["lines"])
    source_lines = [
        (int(line.get("n") or line.get("line") or 0), str(line["text"]))
        for line in source["lines"]
    ]
    notes["source_sha256"] = source["sha256"]
    probe_line = _target_line(raw_slice, sink_line)
    if probe_line <= 0:
        stages.append(StageRecord("P1", False, "no line to watch for this slice"))
        return done(
            TriggerResult(
                case_id=case_id,
                verdict="NOT_EXECUTED",
                residue=None,
                report=await kernel.report(),
                stages=stages,
                notes=notes,
                trace=kernel.trace,
            )
        )
    vars_in_source = sorted(set(_POST_VAR_RE.findall(source_text)))
    param = params[0] if params else (vars_in_source[0] if vars_in_source else "")
    origin_text, origin_line = statement_origin(
        source_lines, probe_line, str(sink.get("code") or "")
    )
    notes.update(
        {
            "probe_line": probe_line,
            "params": params,
            "param": param,
            "statement_origin": origin_line,
            "statement_resolved": origin_line != probe_line,
        }
    )
    stages.append(
        StageRecord("P1", True, f"watch_line={probe_line} param={param or '(unknown)'}")
    )

    # P2 find a page + form that carries the parameter -----------------------------
    page = await kernel.call("http_request", {"method": "GET", "url": base_url})
    status = int(page.get("status", 0))
    body = str(page.get("body", ""))
    notes["page_status"] = status
    forms = forms_from_document(parse(body), str(page.get("final_url") or base_url))
    form = find_form(forms, param) if param else (forms[0] if forms else None)
    if status >= 400 or form is None:
        stages.append(StageRecord("P2", False, f"status={status} forms={len(forms)}"))
        rt.store.set_case_verdict(case_id, "READ_EMPTY", ceiling="EXECUTABLE")
        report = await kernel.report()
        if not report.strip():
            await kernel.call("case_report", {"case_id": case_id, "format": "markdown"})
            report = await kernel.report()
        rt.store.set_case_report(case_id, report)
        write_case_report(rt.store, case_id)
        return done(
            TriggerResult(
                case_id=case_id,
                verdict="READ_EMPTY",
                residue=0,
                report=report,
                stages=stages,
                notes=notes,
                trace=kernel.trace,
            )
        )
    if not param:
        param = form.fields[0].name if form.fields else ""
    carriers = request_carriers(source_text, origin_text, [f.name for f in form.fields])
    if carriers and param not in carriers:
        # The slice's taint parameter is not necessarily the carrier of this
        # statement (a second-order chain may name the login parameter).  Prefer
        # the form field that the statement itself consumes.
        param = carriers[0]
        refound = find_form(forms, param)
        if refound is not None:
            form = refound
    method = (form.method or "POST").upper()
    action = form.action or base_url
    notes.update(
        {
            "form": {"action": action, "method": method, "fields": [f.name for f in form.fields]},
            "param": param,
            "carriers": carriers,
        }
    )
    stages.append(StageRecord("P2", True, f"form={action} method={method} param={param}"))

    # P3 payload candidates come from the class ------------------------------------
    tag = _tag()
    context = sink_class.context(slice_doc, origin_text)
    payloads = sink_class.seed(slice_doc, context, tag, payload_base)
    notes.update({"tag": tag, "context": context, "candidates": payloads})
    stages.append(StageRecord("P3", True, f"context={context} payloads={len(payloads)}"))

    # P4 send bounded shapes; the class decides whether the observation proves it -----
    outcome_level = "NO_DB_OBSERVATION"
    last_outcome: Any = None
    chosen: dict[str, Any] | None = None
    attempts: list[dict[str, Any]] = []
    sent = 0
    try:
        await kernel.call(
            "probe_arm", {"case_id": case_id, "file": sink_file, "line": probe_line}
        )
        for shape, payload in payloads:
            for values in _request_shapes(form, param, payload):
                if sent >= REQUEST_ATTEMPTS:
                    break
                sent += 1
                arguments: dict[str, Any] = {
                    "case_id": case_id,
                    "url": action,
                    "method": method,
                }
                if method == "POST":
                    arguments["body"] = urlencode(values)
                    arguments["headers"] = {
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                else:
                    arguments["params"] = values
                try:
                    run = await kernel.call("probe_run", arguments)
                except ToolCallError as exc:
                    attempts.append(
                        {"shape": shape, "payload": payload, "error": exc.code.value}
                    )
                    continue
                queries = run.get("queries") or []
                sql_texts = [str(q.get("sql") or "") for q in queries if isinstance(q, dict)]
                marker_seen = any(tag in sql for sql in sql_texts)
                error = str(run.get("error") or "")
                facts = {
                    "sql_probe": {
                        "executed": bool(queries),
                        "error": error,
                        "statements": sql_texts[:3],
                    }
                }
                observation = Observation(
                    channel="sql_probe",
                    request={"url": action, "method": method, "values": values},
                    payload=payload,
                    marker_seen=marker_seen,
                    facts=facts,
                )
                outcome = sink_class.accept(observation, context)
                last_outcome = outcome
                attempts.append(
                    {
                        "shape": shape,
                        "payload": payload,
                        "fields": sorted(values),
                        "status": (run.get("http") or {}).get("status"),
                        "marker_seen": marker_seen,
                        "executed": bool(queries),
                        "error": error[:200],
                        "level": outcome.level,
                        "statements": sql_texts[:2],
                    }
                )
                outcome_level = outcome.level
                if outcome.confirmed:
                    chosen = {"shape": shape, "payload": payload, "reason": outcome.reason}
                    break
            if chosen:
                break
    finally:
        with contextlib.suppress(ToolCallError):
            await kernel.call("probe_disarm", {"case_id": case_id})

    # P4.5 blind acceptance: once the in-band diagnosis has run, ask the class for
    # a true/false (or delayed) pair.  Blind evidence is the stricter verdict: it
    # needs both the probe diagnosis and a behavioural differential, so it is only
    # accepted after the diagnosis gate, never on its own.
    blind: dict[str, Any] | None = None
    if hasattr(sink_class, "blind_pairs"):
        pairs = sink_class.blind_pairs(context, tag)
        blind_result = await blind_check(
            kernel,
            case_id=case_id,
            file=sink_file,
            line=probe_line,
            url=action,
            method=method,
            field=param,
            base_values={},
            pairs=pairs,
            tag=tag,
        )
        blind = {
            "kind": blind_result.kind,
            "confirmed": blind_result.confirmed,
            "diagnosis": blind_result.diagnosis,
            "detail": blind_result.detail,
        }
        if blind_result.confirmed:
            true_payload = str(blind_result.detail.get("true_payload") or "")
            observation = Observation(
                channel="blind",
                request={"url": action, "method": method, "values": {param: true_payload}},
                payload=true_payload,
                marker_seen=True,
                facts={"blind": blind},
            )
            outcome = sink_class.accept(observation, context)
            last_outcome = outcome
            outcome_level = outcome.level
            if chosen is None:
                chosen = {
                    "shape": f"blind:{blind_result.kind}",
                    "payload": true_payload,
                    "reason": outcome.reason,
                }
            attempts.append(
                {
                    "shape": chosen["shape"],
                    "payload": true_payload,
                    "level": outcome.level,
                    "blind": blind_result.detail,
                }
            )
        stages.append(
            StageRecord(
                "P4.5",
                blind_result.confirmed,
                f"blind kind={blind_result.kind or '-'} diagnosis={blind_result.diagnosis}",
            )
        )
    notes["blind"] = blind

    notes["attempts"] = attempts
    if chosen:
        notes["payload"] = chosen["payload"]
        notes["payload_shape"] = chosen["shape"]
        notes["payload_constraints"] = {
            "context_kind": context,
            "payload": chosen["payload"],
            "parameter": param,
            "watch_line": probe_line,
        }
    stages.append(
        StageRecord(
            "P4",
            bool(chosen),
            f"attempts={len(attempts)} marker={(chosen or {}).get('shape', '-')}",
        )
    )

    # P5 verdict from the class ------------------------------------------------------
    verdict = trigger_verdict(last_outcome) if last_outcome is not None else "NOT_EXECUTED"
    notes["sql_probe_level"] = outcome_level
    notes["explanation"] = (
        "the payload reached an executed statement"
        if outcome_level == "SQLI_CONFIRMED"
        else "the engine evaluated the injected predicate (blind differential)"
        if outcome_level == "SQLI_BLIND"
        else "the payload did not reach an executed statement"
    )
    stages.append(
        StageRecord("P5", outcome_level in {"SQLI_CONFIRMED", "SQLI_BLIND"}, notes["explanation"])
    )

    # P6 report (no database write, so no undo) --------------------------------------
    # Persist the verdict before rendering it, or the report header says undetermined.
    rt.store.set_case_verdict(case_id, verdict, ceiling="EXECUTABLE")
    report = await kernel.report()
    if not report.strip():
        await kernel.call("case_report", {"case_id": case_id, "format": "markdown"})
        report = await kernel.report()
    rt.store.set_case_report(case_id, report)
    write_case_report(rt.store, case_id)
    stages.append(StageRecord("P6", True, "report written"))
    return done(
        TriggerResult(
            case_id=case_id,
            verdict=verdict,
            residue=0,
            report=report,
            stages=stages,
            notes=notes,
            trace=kernel.trace,
        )
    )
