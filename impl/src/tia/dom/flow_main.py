"""Main agent over the flow queue.

The queue unit is a *flow*: one target read site plus the write sites that can
feed it. Trigger no longer receives an isolated slice; it receives a flow and
acts as the prover. Injection receives the probe's plan and replays it with
legitimate requests only.

Flow building is class-agnostic (see :mod:`tia.orch.flow`), so a SQLi flow is
just another ``sink_class`` on the same queue.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tia.cap.entry import infer_read_entry
from tia.cap.read_evidence import collect_read_sql
from tia.dom.constraint_steps import build_steps
from tia.dom.direct import run_direct
from tia.dom.inject import run_inject
from tia.dom.main import MainResult, _read_target, _report
from tia.dom.prover import run_flow_prover
from tia.dom.rollback import classify_inject
from tia.dom.stages import Stage, rollback
from tia.inf.findings import finding_db_only, finding_first_order, finding_second_order
from tia.inf.reports import RunReports
from tia.inf.runtime import get_runtime
from tia.orch.flow import READ, Site, build_flows, site_role
from tia.orch.identity import direct_identity, identity_of
from tia.orch.kernel import LocalToolClient, ToolClient
from tia.orch.learning import hints_for
from tia.orch.pairing import Reader, resolve_entry
from tia.orch.slicing import score_slice
from tia.schemas.objects import CaseOutcome
from tia.sinks.registry import sink_class_for


@dataclass
class FlowSeedResult:
    sites: int = 0
    flows: int = 0
    flow_ids: list[str] = field(default_factory=list)
    site_ids: list[str] = field(default_factory=list)


def _table_columns(raw: dict[str, Any], index: int, role: str, reader: Reader | None) -> tuple[str, tuple[str, ...]]:
    entry = resolve_entry(raw, index, reader=reader)
    if entry is None or not entry.ops:
        return _read_identity_from_code(raw) if role == READ else ("", ())
    preferred = "insert" if role == "write" else "select"
    for op in entry.ops:
        if op.op == preferred and op.table:
            return op.table, tuple(op.columns)
    for op in entry.ops:
        if op.table:
            return op.table, tuple(op.columns)
    if role == READ:
        return _read_identity_from_code(raw)
    return "", ()


_COLUMN_ACCESS = re.compile(r"\$[A-Za-z_]\w*\s*\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]")
_PROPERTY_ACCESS = re.compile(r"\$[A-Za-z_]\w*->([A-Za-z_]\w*)")


def _columns_in_code(code: str) -> list[str]:
    """Column-looking names a sink expression reads from a row/array."""

    found = _COLUMN_ACCESS.findall(code) + _PROPERTY_ACCESS.findall(code)
    return list(dict.fromkeys(name for name in found if name))


def _read_identity_from_code(raw: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    """Infer the table a second-order sink reads from its own expression.

    A template sink often has no SQL of its own (the query lives in the module
    that includes it), so the only identity available at seeding time is the
    column names the expression touches. Resolve them against the schema and
    pick the table that carries the most of them.
    """

    sink = raw.get("sink")
    sink_data: dict[str, Any] = sink if isinstance(sink, dict) else {}
    code = str(raw.get("sinkCode") or sink_data.get("code") or "")
    columns = _columns_in_code(code)
    if not columns:
        return "", ()
    try:
        rows = get_runtime().mysql.select(
            "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name"
            " FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()"
        ).rows
    except Exception:  # noqa: BLE001 - schema lookup is best effort
        return "", ()
    by_table: dict[str, set[str]] = {}
    for row in rows:
        by_table.setdefault(str(row["table_name"]), set()).add(str(row["column_name"]).lower())
    wanted = {column.lower() for column in columns}
    ranked = sorted(
        ((len(wanted & owned), name) for name, owned in by_table.items()),
        key=lambda item: (-item[0], item[1]),
    )
    if not ranked or ranked[0][0] == 0:
        return "", ()
    table = ranked[0][1]
    matched = tuple(column for column in columns if column.lower() in by_table[table])
    return table, matched


def seed_flow_queue(
    store: Any,
    run_id: str,
    sites: list[dict[str, Any]],
    *,
    family: str = "second",
    reader: Reader | None = None,
) -> FlowSeedResult:
    """Insert sites and build the flows the main agent will lease."""
    result = FlowSeedResult()
    built: list[Site] = []
    for index, item in enumerate(sites):
        raw = dict(item.get("raw") or {})
        site_family = str(item.get("family") or family)
        chain = str(item.get("chain") or "")
        role = str(item.get("role") or site_role(chain, site_family))
        identity = (
            direct_identity(raw) if site_family == "direct" else identity_of(raw, site_family)
        )
        history = store.verdict_history().get(
            f"{raw.get('sinkFile') or ''}:{raw.get('sinkLine') or 0}", []
        )
        scored = score_slice(
            raw,
            paired=role == READ,
            history=history,
            order_mode="direct" if site_family == "direct" else "second",
            learning=hints_for(store, raw),
        )
        table, columns = _table_columns(raw, index, role, reader)
        site_id = store.insert_site(
            run_id,
            raw,
            family=site_family,
            chain=chain,
            role=role,
            identity=identity,
            score=scored.score,
            reasons=scored.reasons,
            digest=scored.digest,
        )
        if site_id is None:
            continue
        result.sites += 1
        result.site_ids.append(site_id)
        raw_sink = raw.get("sink")
        sink: dict[str, Any] = raw_sink if isinstance(raw_sink, dict) else {}
        built.append(
            Site(
                slice_id=site_id,
                raw=raw,
                family=site_family,
                chain=chain,
                role=role,
                kind=str(raw.get("kind") or sink.get("kind") or "Xss"),
                file=str(sink.get("file") or raw.get("sinkFile") or ""),
                line=int(sink.get("line") or raw.get("sinkLine") or 0),
                table=table,
                columns=columns,
                score=scored.score,
                reasons=list(scored.reasons),
            )
        )
    flows = build_flows(built)
    store.seed_flows(run_id, [flow.to_row() for flow in flows])
    result.flows = len(flows)
    result.flow_ids = [flow.flow_id for flow in flows]
    return result


def _read_entry_for(
    reader: Reader | None, raw: dict[str, Any]
) -> dict[str, Any] | None:
    path = str(raw.get("sinkFile") or "")
    line = int(raw.get("sinkLine") or 0)
    if reader is None or not path or not line:
        return None
    try:
        lines = reader(path, max(1, line - 80), line + 10)
    except Exception:  # noqa: BLE001 - entry inference is best effort
        return None
    text = "\n".join(str(value) for _, value in lines)
    method, fields = infer_read_entry(text)
    if not fields:
        return None
    return {
        "method": method,
        "fields": [
            {"name": field.name, "usage": field.usage, "numeric": field.numeric}
            for field in fields
        ],
    }


def _constraint_candidates(
    flow: dict[str, Any],
    plan: dict[str, Any],
    store: Any,
    url_for: Callable[[dict[str, Any]], str] | None,
    base_url: str,
) -> dict[str, list[dict[str, Any]]]:
    """Give every planned constraint the flow's write sites as legal replay candidates."""
    constraints = [item for item in (plan.get("constraints") or []) if isinstance(item, dict)]
    if not constraints:
        return {}
    options: list[dict[str, Any]] = []
    for writer_id in flow.get("writer_slice_ids") or []:
        row = store.get_slice(str(writer_id))
        if row is None:
            continue
        raw = dict(row["slice"])
        options.append(
            {
                "write_slice_id": str(writer_id),
                "score": int(flow.get("score") or 60),
                "table": flow.get("table_name") or flow.get("table") or "",
                "columns": list(flow.get("columns") or []),
                "page_url": url_for(raw) if url_for is not None else base_url,
            }
        )
    return {str(constraint.get("constraint_id") or ""): list(options) for constraint in constraints}


async def run_flow_queue(
    store: Any,
    base_url: str,
    run_id: str | None = None,
    *,
    limit: int = 100,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 120,
    trigger_client: ToolClient | None = None,
    inject_client: ToolClient | None = None,
    url_for: Callable[[dict[str, Any]], str] | None = None,
    reader: Reader | None = None,
) -> MainResult:
    """Lease flows, prove the target, then replay the plan with legal requests."""
    result = MainResult()
    reports = RunReports(store, run_id or "flow")
    for _ in range(max(limit, 0)):
        flow = store.next_flow(run_id)
        if flow is None:
            result.stop_reason = "DONE" if result.outcomes else "NO_FLOW"
            break
        target_row = store.get_slice(str(flow["target_slice_id"]))
        if target_row is None:
            store.archive_flow(str(flow["flow_id"]), "failed", "MISSING_SITE")
            continue
        target_raw = dict(target_row["slice"])
        read_url = url_for(target_raw) if url_for is not None else base_url
        started = time.monotonic()
        if flow.get("family") == "direct":
            # First-order flows have no database step: the direct agent delivers
            # the payload straight to the page and verifies the reflection.
            try:
                direct = await run_direct(
                    target_raw,
                    base_url=read_url,
                    payload_base=payload_base,
                    budget=min(budget, 40),
                    client=inject_client,
                    slice_id=str(flow["target_slice_id"]),
                )
            except Exception as exc:  # noqa: BLE001 - keep the queue alive
                store.archive_flow(str(flow["flow_id"]), "failed", "ERROR", notes={"error": str(exc)})
                continue
            if direct.verdict == "EXECUTED":
                finding_first_order(store, direct.case_id)
            store.archive_slice(str(flow["target_slice_id"]), direct.verdict, case_id=direct.case_id)
            store.archive_flow(
                str(flow["flow_id"]),
                "reported" if direct.verdict == "EXECUTED" else "failed",
                direct.verdict,
                case_id=direct.case_id,
                notes={"flow_id": flow["flow_id"], "stage": "direct"},
            )
            reports.add(direct.case_id, "direct", direct.verdict, flow["flow_id"])
            result.outcomes.append(
                CaseOutcome(
                    slice_id=str(flow["flow_id"]),
                    case_id=direct.case_id,
                    verdict=direct.verdict,
                    evidence_refs=[step.evidence_ref for step in direct.trace if step.evidence_ref],
                    residue=direct.residue or 0,
                    notes={"flow_id": flow["flow_id"], "stage": "direct"},
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            )
            continue
        try:
            probe, trigger = await run_flow_prover(
                flow,
                target_raw,
                read_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=trigger_client,
                slice_id=str(flow["target_slice_id"]),
            )
        except Exception as exc:  # noqa: BLE001 - one bad flow must not stop the queue
            store.archive_flow(str(flow["flow_id"]), "failed", "ERROR", notes={"error": str(exc)})
            continue
        store.set_flow_probe(str(flow["flow_id"]), probe.to_dict())
        store.archive_slice(
            str(flow["target_slice_id"]), trigger.verdict, case_id=trigger.case_id
        )
        notes: dict[str, Any] = {
            "flow_id": flow["flow_id"],
            "flow_class": flow["sink_class"],
            "trigger": trigger.verdict,
            "trigger_case": trigger.case_id,
            "plan_constraints": len(probe.constraints),
        }
        verdict = trigger.verdict
        case_id = trigger.case_id
        residue = trigger.residue or 0
        refs = list(probe.evidence_refs)
        success = trigger.verdict == "EXECUTED" and residue == 0
        flow_class = sink_class_for(str(flow.get("sink_class") or ""))
        # A class that never persists a payload needs no replay step: the prover
        # is the whole proof, so the flow ends here regardless of writers.
        if not flow_class.writes_database():
            proof_notes = {"flow_class": flow_class.name}
            store.archive_flow(
                str(flow["flow_id"]),
                "reported" if success else "failed",
                verdict,
                case_id=case_id,
                notes=proof_notes,
            )
            reports.add(case_id, flow_class.name, verdict, str(flow["flow_id"]))
            result.outcomes.append(
                CaseOutcome(
                    slice_id=str(flow["flow_id"]),
                    case_id=case_id,
                    verdict=verdict,
                    evidence_refs=refs,
                    residue=residue,
                    notes=proof_notes,
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            )
            continue
        if success:
            writer_raw, writer_id = target_raw, str(flow["target_slice_id"])
            for candidate_id in flow.get("writer_slice_ids") or []:
                row = store.get_slice(str(candidate_id))
                if row is not None:
                    writer_raw, writer_id = dict(row["slice"]), str(candidate_id)
                    break
            write_url = url_for(writer_raw) if url_for is not None else base_url
            raw_plan = (probe.notes or {}).get("constraint_plan")
            plan: dict[str, Any] = raw_plan if isinstance(raw_plan, dict) else {}
            client = inject_client or trigger_client or LocalToolClient("inject")

            async def _call(
                name: str,
                arguments: dict[str, Any],
                _client: Any = client,
            ) -> dict[str, Any]:
                envelope = await _client.call(name, arguments)
                data = getattr(envelope, "data", envelope)
                return dict(data or {})

            read_sql = ""
            read_trace: dict[str, Any] = {}
            if not plan.get("constraints"):
                # The template shows a row; the query that selected it lives one
                # level up. Trace points at the executed lines and the probe
                # reports the statement itself, so the condition comes from what
                # the engine ran rather than from a source-level guess.
                try:
                    evidence = await collect_read_sql(
                        _call,
                        case_id=case_id,
                        url=read_url,
                        sink_file=str(target_raw.get("sinkFile") or ""),
                        sink_line=int(target_raw.get("sinkLine") or 0),
                    )
                    notes["read_trace"] = evidence.get("trace_id") or ""
                    notes["read_executed"] = evidence.get("executed") or {}
                    read_trace = evidence.get("trace") or {}
                    if read_trace.get("entries"):
                        notes["read_trace_slice"] = read_trace
                    statements = evidence.get("statements") or []
                    if statements:
                        read_sql = str(statements[0])
                        notes["read_sql"] = read_sql
                except Exception as exc:  # noqa: BLE001 - evidence is best effort
                    notes["read_evidence_error"] = str(exc)
            if not plan.get("constraints"):
                writers: list[tuple[str, dict[str, Any]]] = []
                seen_writers: set[str] = set()
                for writer_id in flow.get("writer_slice_ids") or []:
                    row = store.get_slice(str(writer_id))
                    if row is not None:
                        writers.append((str(writer_id), dict(row["slice"])))
                        seen_writers.add(str(writer_id))
                for row in store.list_slice_rows(run_id=run_id, limit=2000):
                    if str(row.get("role") or "") != "write":
                        continue
                    if str(row.get("id")) in seen_writers:
                        continue
                    raw_candidate = row.get("slice")
                    if isinstance(raw_candidate, dict):
                        writers.append((str(row.get("id")), dict(raw_candidate)))
                        seen_writers.add(str(row.get("id")))
                if writers:
                    from tia.inf.accounts import public_catalog

                    planner = None
                    try:
                        from tia.ad.llm import LlmClient

                        planner = LlmClient.from_env()
                    except Exception:  # noqa: BLE001 - the planner is optional
                        planner = None
                    plan = await build_steps(
                        _call,
                        flow,
                        writers,
                        base_url,
                        url_for,
                        public_catalog(get_runtime().settings.accounts_path),
                        read_raw=target_raw,
                        read_sql=read_sql,
                        read_trace=read_trace,
                        planner=planner,
                    )
            entry = _read_entry_for(reader, target_raw)
            pair_map = _constraint_candidates(flow, plan, store, url_for, base_url)
            hint = {
                "pair_id": str(flow["flow_id"]),
                "table": flow.get("table_name") or flow.get("table") or "",
                "columns": list(flow.get("columns") or []),
                "confidence": int(flow.get("score") or 60),
                "direction": "write_then_read",
            }
            inject: Any = None
            async def _stage_inject(
                ctx: dict[str, Any],
                *,
                _writer_raw: dict[str, Any] = writer_raw,
                _write_url: str = write_url,
                _payload_base: str = payload_base,
                _budget: int = budget,
                _client: Any = inject_client,
                _hint: dict[str, Any] = hint,
                _read_url: str = read_url,
                _entry: Any = entry,
                _probe: Any = probe,
                _writer_id: str = writer_id,
                _target_raw: dict[str, Any] = target_raw,
                _plan: dict[str, Any] = plan,
                _pair_map: dict[str, Any] = pair_map,
                _flow: dict[str, Any] = flow,
            ) -> None:
                nonlocal inject
                inject = await run_inject(
                    _writer_raw,
                    base_url=_write_url,
                    payload_base=_payload_base,
                    budget=min(_budget, 40),
                    client=_client,
                    pair_hints=[dict(_hint)],
                    verify_url=_read_url,
                    verify_entry=_entry,
                    verify_values=(_probe.notes or {}).get("read_entry_values"),
                    payload_constraints=_probe.notes.get("payload_constraints"),
                    slice_id=_writer_id,
                    learning=hints_for(store, _target_raw),
                    read_target=_read_target(_target_raw, _probe.notes),
                    constraint_plan=_plan,
                    pair_candidates=_pair_map,
                    flow=_flow,
                    feedback=str(ctx.get("feedback") or ""),
                    shape_hint=str(ctx.get("shape_hint") or ""),
                )

            inject = await run_inject(
                writer_raw,
                base_url=write_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=inject_client,
                pair_hints=[hint],
                verify_url=read_url,
                verify_entry=entry,
                verify_values=(probe.notes or {}).get("read_entry_values"),
                payload_constraints=probe.notes.get("payload_constraints"),
                slice_id=writer_id,
                learning=hints_for(store, target_raw),
                read_target=_read_target(target_raw, probe.notes),
                constraint_plan=plan,
                pair_candidates=pair_map,
                flow=flow,
            )
            failure = classify_inject(inject)
            if failure is not None:
                # A failed final check is not a reason to restart the flow:
                # trigger proved the read path and pairing produced the write
                # slice, so only the stage the cause points at (and the stages
                # that depend on it) is replayed once, with the failure detail.
                stage_ctx: dict[str, Any] = {
                    "feedback": failure.detail or failure.reason,
                    "shape_hint": failure.shape_hint,
                }

                stages = [
                    Stage("trigger", (), None),
                    Stage("pair", ("trigger",), None),
                    Stage("inject", ("pair",), _stage_inject),
                ]
                done = await rollback(
                    stages, stage_ctx, failure.stage, reason=failure.reason
                )
                notes["rollback"] = {
                    "target": done.target,
                    "rerun": done.rerun,
                    "reason": done.reason,
                    "attempt": done.attempt,
                    "detail": failure.detail,
                    "shape_hint": failure.shape_hint,
                    "verdict": inject.verdict,
                }
            verdict = inject.verdict
            case_id = inject.case_id
            residue = inject.residue or 0
            refs += [step.evidence_ref for step in inject.trace if step.evidence_ref]
            notes["inject"] = inject.verdict
            notes["inject_case"] = inject.case_id
            store.archive_slice(writer_id, inject.verdict, case_id=inject.case_id)
            if inject.verdict in {"EXECUTABLE", "EXECUTED"}:
                finding_second_order(store, inject.case_id)
            else:
                finding_db_only(store, trigger.case_id)
            reports.add(
                inject.case_id,
                "inject",
                inject.verdict,
                f"{flow.get('table') or '?'}.{','.join(flow.get('columns') or []) or '?'}",
            )
        store.archive_flow(
            str(flow["flow_id"]),
            "reported" if verdict in {"EXECUTABLE", "EXECUTED"} else "failed",
            verdict,
            case_id=case_id,
            notes=notes,
        )
        result.outcomes.append(
            CaseOutcome(
                slice_id=str(flow["flow_id"]),
                case_id=case_id,
                verdict=verdict,
                evidence_refs=[ref for ref in refs if ref],
                residue=residue,
                notes=notes,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        )
    else:
        if run_id and store.count_pending_flows(run_id) > 0:
            result.stop_reason = "LIMIT_REACHED"
    index = reports.finish(result.stop_reason, len(result.outcomes), len(result.outcomes))
    result.report_path = str(index)
    result.report = _report(result)
    return result
