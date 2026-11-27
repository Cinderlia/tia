"""Main agent over the flow queue.

The queue unit is a *flow*: one target read site plus the write sites that can
feed it. Trigger no longer receives an isolated slice; it receives a flow and
acts as the prover. Injection receives the probe's plan and replays it with
legitimate requests only.

Flow building is class-agnostic (see :mod:`tia.orch.flow`), so a SQLi flow is
just another ``sink_class`` on the same queue.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tia.cap.entry import infer_read_entry
from tia.dom.direct import run_direct
from tia.dom.inject import run_inject
from tia.dom.main import MainResult, _read_target, _report
from tia.dom.prover import run_flow_prover
from tia.inf.findings import finding_db_only, finding_first_order, finding_second_order
from tia.inf.reports import RunReports
from tia.orch.flow import READ, Site, build_flows, site_role
from tia.orch.identity import direct_identity, identity_of
from tia.orch.kernel import ToolClient
from tia.orch.learning import hints_for
from tia.orch.pairing import Reader, resolve_entry
from tia.orch.slicing import score_slice
from tia.schemas.objects import CaseOutcome


@dataclass
class FlowSeedResult:
    sites: int = 0
    flows: int = 0
    flow_ids: list[str] = field(default_factory=list)
    site_ids: list[str] = field(default_factory=list)


def _table_columns(raw: dict[str, Any], index: int, role: str, reader: Reader | None) -> tuple[str, tuple[str, ...]]:
    entry = resolve_entry(raw, index, reader=reader)
    if entry is None or not entry.ops:
        return "", ()
    preferred = "insert" if role == "write" else "select"
    for op in entry.ops:
        if op.op == preferred and op.table:
            return op.table, tuple(op.columns)
    for op in entry.ops:
        if op.table:
            return op.table, tuple(op.columns)
    return "", ()


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
                "table": flow.get("table") or "",
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
            entry = _read_entry_for(reader, target_raw)
            pair_map = _constraint_candidates(flow, plan, store, url_for, base_url)
            hint = {
                "pair_id": str(flow["flow_id"]),
                "table": flow.get("table") or "",
                "columns": list(flow.get("columns") or []),
                "confidence": int(flow.get("score") or 60),
                "direction": "write_then_read",
            }
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
