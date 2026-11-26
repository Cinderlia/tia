"""``tia-agent`` entry point: trigger / inject / main.

The three subcommands share the same profile / config loading; stage logs go to stderr, result JSON goes to stdout.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from tia import __version__
from tia.cap.registry import dispatch as registry_dispatch
from tia.dom.inject import InjectResult, run_inject
from tia.dom.main import MainResult, run_injection_queue, run_main, run_queue, seed_queue
from tia.dom.pairing_agent import PairingConfig, build_pairing_queue
from tia.dom.trigger import TriggerResult, run_trigger
from tia.inf.config import Settings
from tia.inf.runtime import configure, get_runtime
from tia.orch.kernel import ToolCallError

PROFILES = ("trigger", "inject", "main")


def _add_common(parser: argparse.ArgumentParser, *, base_url_required: bool) -> None:
    parser.add_argument("--slice", required=True, help="Slice JSON file (navi sink/slice or Slice)")
    parser.add_argument("--index", type=int, default=0, help="Index when the file is an array/multiple sinks")
    parser.add_argument("--base-url", required=base_url_required, help="Target page URL (use 127.0.0.1 inside container)")
    parser.add_argument("--payload", default="<script>alert(1)</script>", help="Base payload")
    parser.add_argument("--budget", type=int, default=40)
    parser.add_argument("--db-name", default=None, help="Target database name (defaults to reading TIA_DB_NAME)")
    parser.add_argument("--db-user", default=None)
    parser.add_argument("--db-password", default=None)
    parser.add_argument("--store", default=None, help="sqlite path (defaults to impl/var/tia.db)")
    parser.add_argument(
        "--account",
        default="",
        help="Account label pinned for this run (defaults to the first account matching the URL)",
    )
    parser.add_argument("--json", action="store_true", help="stdout outputs only result JSON")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tia-agent", description="TIA agent")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    trigger = sub.add_parser("trigger", help="Execute P0–P6 trigger forensics on the slice")
    _add_common(trigger, base_url_required=True)

    inject = sub.add_parser("inject", help="Execute I0–I7 injection forensics on the slice")
    _add_common(inject, base_url_required=True)
    inject.add_argument("--no-cleanup", action="store_true", help="Retain written data, do not delete")

    main_cmd = sub.add_parser("main", help="Schedule multiple slices: trigger → inject → archive")
    main_cmd.add_argument("--slices", required=True, help="Slice JSON file (array/object containing sinks|slices)")
    main_cmd.add_argument("--base-url", required=True)
    main_cmd.add_argument("--limit", type=int, default=1, help="Max number of slices to schedule this round")
    main_cmd.add_argument("--payload", default="<script>alert(1)</script>")
    main_cmd.add_argument("--budget", type=int, default=120)
    main_cmd.add_argument("--db-name", default=None)
    main_cmd.add_argument("--db-user", default=None)
    main_cmd.add_argument("--db-password", default=None)
    main_cmd.add_argument("--store", default=None)
    main_cmd.add_argument("--run-id", default=None, help="Queue run id; slices are seeded under it")
    main_cmd.add_argument(
        "--queue",
        action="store_true",
        help="Seed the slices into the persistent queue and schedule from it (M0-M6)",
    )
    main_cmd.add_argument(
        "--inject-queue",
        action="store_true",
        help="Build the pairing queue (read/write pairs) and walk it with trigger+inject",
    )
    main_cmd.add_argument("--cap", type=int, default=10, help="Injection queue cap (time control)")
    main_cmd.add_argument("--trigger-only", action="store_true", help="Run trigger only, no inject")
    main_cmd.add_argument(
        "--per-slice-url",
        action="store_true",
        help="Derive the page URL from each slice's sink directory",
    )
    main_cmd.add_argument("--write-slices", default=None, help="Write-side slices for the pairing queue")
    main_cmd.add_argument("--json", action="store_true")

    pairing = sub.add_parser("pairing", help="Match read/write slices and rank the injection queue")
    pairing.add_argument(
        "--write-slices", required=True, help="Injection slices (navi inject 1-write)"
    )
    pairing.add_argument(
        "--read-run-id", required=True, help="Trigger run whose proven slices form the read side"
    )
    pairing.add_argument("--run-id", default=None)
    pairing.add_argument("--cap", type=int, default=10, help="Queue cap (time control)")
    pairing.add_argument("--max-slices", type=int, default=2000)
    pairing.add_argument("--max-source-reads", type=int, default=400)
    pairing.add_argument("--no-source", action="store_true", help="Static ops only")
    pairing.add_argument("--db-name", default=None)
    pairing.add_argument("--db-user", default=None)
    pairing.add_argument("--db-password", default=None)
    pairing.add_argument("--store", default=None)
    pairing.add_argument("--json", action="store_true")

    direct = sub.add_parser("direct", help="First-order agent: deliver a payload, verify the page")
    direct.add_argument("--slice", required=True, help="Navi direct slice file")
    direct.add_argument("--index", type=int, default=0)
    direct.add_argument("--base-url", required=True)
    direct.add_argument("--budget", type=int, default=40)
    direct.add_argument("--db-name", default=None)
    direct.add_argument("--db-user", default=None)
    direct.add_argument("--db-password", default=None)
    direct.add_argument("--store", default=None)
    direct.add_argument("--json", action="store_true")
    accounts = sub.add_parser("accounts", help="List configured accounts (never prints passwords)")
    accounts.add_argument("--accounts", default=None, help="accounts.yaml path")
    accounts.add_argument("--store", default=None)
    accounts.add_argument("--json", action="store_true")

    login = sub.add_parser("login", help="Bind one account over HTTP and store its session cookies")
    login.add_argument("--label", default="", help="Account label")
    login.add_argument("--roles", default="", help="Comma separated required roles")
    login.add_argument("--base-url", default="", help="Restrict the account to this application URL")
    login.add_argument("--case-id", default=None)
    login.add_argument("--accounts", default=None, help="accounts.yaml path")
    login.add_argument("--store", default=None)
    login.add_argument("--json", action="store_true")

    browser_install = sub.add_parser(
        "browser-install", help="Download Chrome for Testing used by execution confirmation"
    )
    browser_install.add_argument("--version", default=None, help="Chrome version (default: pinned build)")
    browser_install.add_argument("--force", action="store_true", help="Re-download even when present")
    browser_install.add_argument("--json", action="store_true")

    browser_check = sub.add_parser(
        "browser-check", help="Show which Chrome the execution confirmation would use"
    )
    browser_check.add_argument("--json", action="store_true")

    pipeline = sub.add_parser(
        "pipeline",
        help="Main → trigger proof → pairing → injection queue (one stage failure stops downstream)",
    )
    pipeline.add_argument(
        "--slices",
        default=None,
        help="Second-order trigger slices (navi trigger/joined); optional in direct-only runs",
    )
    pipeline.add_argument(
        "--direct-slices",
        default=None,
        help="First-order slices (navi direct/1-output); not inferred, the tree decides",
    )
    pipeline.add_argument(
        "--write-slices",
        default=None,
        help="Injection slices (navi inject/1-write); only needed for second-order rounds",
    )
    pipeline.add_argument(
        "--mode",
        default="second",
        choices=["direct", "second", "direct-first", "second-first", "hybrid"],
        help="Slice consumption policy",
    )
    pipeline.add_argument("--base-url", required=True)
    pipeline.add_argument("--timeout", type=float, default=600.0, help="Wall-clock budget in seconds")
    pipeline.add_argument("--limit", type=int, default=0, help="Max trigger slices (0 = until timeout/exhaustion)")
    pipeline.add_argument("--cap", type=int, default=10, help="Injection queue cap")
    pipeline.add_argument("--payload", default="<script>alert(1)</script>")
    pipeline.add_argument("--budget", type=int, default=120)
    pipeline.add_argument("--db-name", default=None)
    pipeline.add_argument("--db-user", default=None)
    pipeline.add_argument("--db-password", default=None)
    pipeline.add_argument("--store", default=None)
    pipeline.add_argument("--run-id", default=None)
    pipeline.add_argument(
        "--per-slice-url",
        action="store_true",
        help="Derive the page URL from each slice's sink directory",
    )
    pipeline.add_argument(
        "--reports",
        default=None,
        help="Report directory for this run (default: <store dir>/reports)",
    )
    pipeline.add_argument("--json", action="store_true")
    return parser


def _load_slice(path: str, index: int) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    candidates: Any = raw
    if isinstance(raw, dict):
        for key in ("sinks", "slices"):
            if key in raw and isinstance(raw[key], list):
                candidates = raw[key]
                break
    if isinstance(candidates, list):
        if not candidates:
            raise SystemExit("No entries in slice file")
        return dict(candidates[index])
    if isinstance(raw, dict):
        return raw
    raise SystemExit("Slice file must be an object or array")


def _load_slices(path: str) -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [dict(item) for item in raw]
    if isinstance(raw, dict):
        for key in ("sinks", "slices"):
            if isinstance(raw.get(key), list):
                return [dict(item) for item in raw[key]]
        return [dict(raw)]
    raise SystemExit("Slice file must be an object or array")


def _print_stages(stages: list[Any]) -> None:
    for stage in stages:
        mark = "ok" if stage.ok else "!!"
        print(f"[{stage.stage}] {mark} {stage.note}", file=sys.stderr)


def _configure(args: argparse.Namespace, profile: str) -> Settings:
    settings = Settings.load(
        profile,
        db_name=args.db_name,
        db_user=args.db_user,
        db_password=args.db_password,
        store_path=Path(args.store) if args.store else None,
    )
    configure(settings)
    return settings


def _fail(exc: ToolCallError) -> int:
    payload = {
        "ok": False,
        "tool": exc.tool,
        "error": exc.envelope.error.model_dump() if exc.envelope.error else None,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 2


def _run_trigger(args: argparse.Namespace) -> int:
    _configure(args, "trigger")
    slice_doc = _load_slice(args.slice, args.index)
    try:
        result: TriggerResult = asyncio.run(
            run_trigger(slice_doc, base_url=args.base_url, payload_base=args.payload, budget=args.budget)
        )
    except ToolCallError as exc:
        return _fail(exc)
    _print_stages(result.stages)
    summary = {
        "ok": True,
        "agent": "trigger",
        "case_id": result.case_id,
        "verdict": result.verdict,
        "residue": result.residue,
        "table": result.notes.get("table"),
        "tag": result.notes.get("tag"),
        "occurrence_count": result.notes.get("occurrence_count"),
        "change_id": result.notes.get("change_id"),
        "payload_constraints": result.notes.get("payload_constraints"),
        "execution": result.notes.get("execution"),
        "explanation": result.notes.get("explanation"),
        "tool_calls": len(result.trace),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if result.verdict == "EXECUTED":
        from tia.inf.findings import finding_db_only

        finding_db_only(get_runtime().store, result.case_id)
    if not args.json:
        print(result.report)
    return 0


def _run_inject(args: argparse.Namespace) -> int:
    _configure(args, "inject")
    slice_doc = _load_slice(args.slice, args.index)
    try:
        result: InjectResult = asyncio.run(
            run_inject(
                slice_doc,
                base_url=args.base_url,
                payload_base=args.payload,
                budget=args.budget,
                cleanup=not args.no_cleanup,
            )
        )
    except ToolCallError as exc:
        return _fail(exc)
    _print_stages(result.stages)
    summary = {
        "ok": True,
        "agent": "inject",
        "case_id": result.case_id,
        "verdict": result.verdict,
        "residue": result.residue,
        "tag": result.notes.get("tag"),
        "target": result.notes.get("target"),
        "tag_in_db": result.notes.get("tag_in_db"),
        "tag_in_page": result.notes.get("tag_in_page"),
        "context_kind": result.notes.get("context_kind"),
        "explanation": result.notes.get("explanation"),
        "tool_calls": len(result.trace),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not args.json:
        print(result.report)
    return 0


def _run_main(args: argparse.Namespace) -> int:
    _configure(args, "main")
    slices = _load_slices(args.slices)
    if getattr(args, "write_slices", None):
        slices = slices + _load_slices(args.write_slices)
    run_id = args.run_id or f"run-{int(time.time())}"
    def url_for(raw: dict[str, Any]) -> str:
        parent = str(Path(str(raw.get("sinkFile") or "")).parent).strip(".")
        if not parent:
            return str(args.base_url)
        return str(args.base_url).rstrip("/") + "/" + parent.strip("/") + "/"

    url_for_fn = url_for if args.per_slice_url else None
    result: MainResult
    try:
        if args.inject_queue:
            store = get_runtime().store
            result = asyncio.run(
                run_injection_queue(
                    store,
                    base_url=args.base_url,
                    run_id=run_id,
                    limit=args.cap,
                    payload_base=args.payload,
                    budget=args.budget,
                    url_for=url_for_fn,
                )
            )
        elif args.queue:
            store = get_runtime().store
            seed_queue(store, run_id, slices)
            result = asyncio.run(
                run_queue(
                    store,
                    base_url=args.base_url,
                    run_id=run_id,
                    limit=args.limit,
                    payload_base=args.payload,
                    budget=args.budget,
                    trigger_only=args.trigger_only,
                    url_for=url_for_fn,
                )
            )
        else:
            result = asyncio.run(
                run_main(
                    slices,
                    base_url=args.base_url,
                    limit=args.limit,
                    payload_base=args.payload,
                    budget=args.budget,
                )
            )
    except ToolCallError as exc:
        return _fail(exc)
    for item in result.outcomes:
        print(f"[{item.slice_id}] {item.verdict}", file=sys.stderr)
    summary = {
        "ok": True,
        "agent": "main",
        "attempted": len(result.outcomes),
        "stop_reason": result.stop_reason,
        "run_id": run_id if args.queue else None,
        "outcomes": [item.model_dump() for item in result.outcomes],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not args.json:
        print(result.report)
    return 0


def _run_pairing(args: argparse.Namespace) -> int:
    from tia.ad.fs import FsAdapter

    _configure(args, "main")
    store = get_runtime().store
    writes = _load_slices(args.write_slices)
    proven = store.list_slice_rows(args.read_run_id, verdicts=("EXECUTED", "EXECUTABLE"))
    run_id = args.run_id or f"pair-{int(time.time())}"

    reader = None
    if not args.no_source:
        adapter = FsAdapter(get_runtime().settings.app_root)

        def reader(path: str, line_from: int, line_to: int) -> list[tuple[int, str]]:
            return adapter.read(path, line_from, line_to).lines

    result = build_pairing_queue(
        store,
        run_id,
        writes,
        proven,
        reader=reader,
        config=PairingConfig(
            max_slices=args.max_slices,
            max_source_reads=args.max_source_reads,
            queue_cap=args.cap,
        ),
    )
    for stage in result.stages:
        print(f"[{stage.stage}] {'ok' if stage.ok else '!!'} {stage.note}", file=sys.stderr)
    summary = {
        "ok": True,
        "agent": "pairing",
        "run_id": run_id,
        "slices": result.n_slices,
        "proven_reads": len(proven),
        "pairs": result.n_pairs,
        "queued": len(result.queue),
        "notes": result.notes,
        "queue": [
            {
                "item_id": item["item_id"],
                "score": item["score"],
                "write": item["write_slice_id"],
                "read": item["read_slice_id"],
                "table": item["table"],
                "columns": item["columns"],
            }
            for item in result.queue[:20]
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def _run_direct(args: argparse.Namespace) -> int:
    from tia.dom.direct import run_direct

    _configure(args, "inject")
    raw = _load_slice(args.slice, args.index)
    result = asyncio.run(
        run_direct(
            raw,
            base_url=args.base_url,
            budget=args.budget,
        )
    )
    for stage in result.stages:
        print(f"[{stage.stage}] {stage.note}", file=sys.stderr)
    print(result.verdict, file=sys.stderr)
    summary = {
        "ok": True,
        "agent": "direct",
        "case_id": result.case_id,
        "verdict": result.verdict,
        "stage": [[stage.stage, stage.ok, stage.note] for stage in result.stages],
        "notes": result.notes,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if result.verdict == "EXECUTED":
        from tia.inf.findings import finding_first_order

        finding_first_order(get_runtime().store, result.case_id)
    if not args.json:
        print(result.report)
    return 0 if result.verdict == "EXECUTED" else 1


def _run_pipeline(args: argparse.Namespace) -> int:
    from tia.dom.pipeline import run_pipeline

    if args.mode == "direct" and not args.direct_slices:
        raise SystemExit("--mode direct needs --direct-slices")
    if args.mode != "direct" and not args.slices:
        raise SystemExit(f"--mode {args.mode} needs --slices (second-order trigger slices)")
    if args.mode != "direct" and not args.write_slices:
        raise SystemExit(f"--mode {args.mode} needs --write-slices (injection slices)")

    if args.reports:
        os.environ["TIA_REPORTS"] = args.reports
    _configure(args, "main")
    store = get_runtime().store
    trigger_slices = _load_slices(args.slices) if args.slices else []
    write_slices = _load_slices(args.write_slices) if args.write_slices else []
    direct_slices = _load_slices(args.direct_slices) if args.direct_slices else []
    run_id = args.run_id or f"pipe-{int(time.time())}"

    def url_for(raw: dict[str, Any]) -> str:
        parent = str(Path(str(raw.get("sinkFile") or "")).parent).strip(".")
        if not parent:
            return str(args.base_url)
        return str(args.base_url).rstrip("/") + "/" + parent.strip("/") + "/"

    url_for_fn = url_for if args.per_slice_url else None
    result = asyncio.run(
        run_pipeline(
            store,
            trigger_run_id=run_id,
            trigger_slices=trigger_slices,
            write_slices=write_slices,
            base_url=args.base_url,
            timeout_sec=args.timeout,
            max_slices=args.limit,
            payload_base=args.payload,
            budget=args.budget,
            queue_cap=args.cap,
            url_for=url_for_fn,
            direct_slices=direct_slices,
            mode=args.mode,
        )
    )
    for item in result.outcomes:
        print(f"[{item.notes.get('stage', '')}] [{item.slice_id}] {item.verdict}", file=sys.stderr)
    summary = {
        "ok": True,
        "agent": "pipeline",
        "mode": args.mode,
        "run_id": run_id,
        "stop_reason": result.stop_reason,
        "rounds": result.rounds,
        "outcomes": [item.model_dump() for item in result.outcomes],
        "report_path": result.report_path,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"[report] {result.report_path}", file=sys.stderr)
    if not args.json:
        print(result.report)
    return 0


def _prepare_env(args: argparse.Namespace, profile: str = "trigger") -> None:
    if getattr(args, "accounts", None):
        os.environ["TIA_ACCOUNTS"] = args.accounts
    if getattr(args, "account", ""):
        os.environ["TIA_ACCOUNT"] = args.account
    settings = Settings.load(profile, store_path=args.store)
    configure(settings)


def _dispatch_session(payload: dict[str, Any]) -> dict[str, Any]:
    envelope = asyncio.run(registry_dispatch("trigger", "session_bind", payload))
    if not envelope.ok:
        error = envelope.error
        raise SystemExit(
            json.dumps(
                {"ok": False, "tool": "session_bind", "error": error.model_dump() if error else None},
                ensure_ascii=False,
            )
        )
    return dict(envelope.data) if isinstance(envelope.data, dict) else {}


def _run_accounts(args: argparse.Namespace) -> int:
    _prepare_env(args)
    data = _dispatch_session({})
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    for account in data.get("accounts", []):
        roles = ",".join(account.get("roles") or []) or "-"
        print(
            f"{account.get('label')}\t{account.get('base_url')}\troles={roles}"
            f"\t{account.get('description', '')}"
        )
    return 0


def _run_login(args: argparse.Namespace) -> int:
    _prepare_env(args, "trigger")
    roles = [item.strip() for item in args.roles.split(",") if item.strip()]
    data = _dispatch_session(
        {
            "account_label": args.label,
            "roles": roles,
            "base_url": args.base_url,
            "case_id": args.case_id,
        }
    )
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    print(
        f"session {data.get('session_id')} label={data.get('label')}"
        f" roles={','.join(data.get('roles') or []) or '-'}"
        f" cookies={data.get('cookie_count')} reused={data.get('reused')}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"tia-agent {__version__}")
        return 0
    if args.command is None:
        parser.error(
            "Subcommand required: direct | trigger | inject | main | pairing | pipeline"
            " | accounts | login | browser-install | browser-check"
        )
    handlers = {
        "direct": _run_direct,
        "trigger": _run_trigger,
        "inject": _run_inject,
        "main": _run_main,
        "pairing": _run_pairing,
        "pipeline": _run_pipeline,
        "accounts": _run_accounts,
        "login": _run_login,
        "browser-install": _run_browser_install,
        "browser-check": _run_browser_check,
    }
    return handlers[args.command](args)


def _run_browser_install(args: argparse.Namespace) -> int:
    from tia.inf.browser_setup import BrowserSetupError, install_chrome

    try:
        result = install_chrome(args.version, force=args.force)
    except BrowserSetupError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


def _run_browser_check(args: argparse.Namespace) -> int:
    from tia.inf import browser_setup

    status = browser_setup.status()
    print(json.dumps(status, indent=2))
    return 0 if status.get("available") else 1
