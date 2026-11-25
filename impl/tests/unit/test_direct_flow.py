"""Direct (first-order) agent tests: candidate delivery and the verdict matrix.

The mock client keeps the flow decisions (attempt order, when to stop, what
verdict) independent from any live page.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom.direct import _PAYLOADS, run_direct
from tia.dom.pipeline import pick_family
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

SOURCE = """
$target = $_REQUEST["target"];
$cmd = shell_exec("ping " . $target);
echo "<pre>" . $cmd . "</pre>";
"""


class DirectClient:
    def __init__(self, *, executable_at: int | None = 0, found: bool = True) -> None:
        self.calls: list[str] = []
        self.executable_at = executable_at
        self.found = found
        self.page_fetched = False

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        return Envelope.success(
            tool=tool, profile="inject", data=self._data(tool, arguments or {}), cost_ms=1
        )

    def _data(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "case_open":
            return {"case_id": "case-direct", "read_point": {}, "open_questions": []}
        if tool == "case_report":
            return {"case_id": "case-direct", "markdown": "# report"}
        if tool == "case_note":
            return {"ok": True, "revision": 1}
        if tool == "source_read":
            return {
                "file": "vulnerabilities/cmdi/home.php",
                "total_lines": 12,
                "sha256": "abc",
                "lines": [
                    {"n": i + 1, "text": line, "in_comment": False, "in_string": False}
                    for i, line in enumerate(SOURCE.splitlines())
                ],
            }
        if tool == "http_request":
            if not self.page_fetched:
                self.page_fetched = True
                return {
                    "status": 200,
                    "body": '<form action="home.php" method="post"><input name="target"></form>',
                    "content_type": "text/html",
                }
            return {"status": 200, "body": "<html><body>echo</body></html>", "content_type": "text/html"}
        if tool == "verify_tag":
            nth = sum(1 for item in self.calls if item == "verify_tag") - 1
            executable = (
                self.found and self.executable_at is not None and nth >= self.executable_at
            )
            return {
                "found": self.found,
                "occurrence_count": 1 if self.found else 0,
                "encoded_count": 0,
                "occurrences": [],
                "best": {
                    "executable": executable,
                    "context_kind": "html_text",
                    "executable_reason": "HTML_EXECUTABLE" if executable else "INERT_PAYLOAD",
                    "node_path": "html>body>pre",
                },
                "verdict_ceiling": "EXECUTABLE",
            }
        return {}


@pytest.fixture()
def runtime(tmp_path: Path) -> Any:
    settings = Settings.load("inject", store_path=tmp_path / "tia.db", app_root=Path("/app/xvwa"))
    configure(settings)
    yield settings
    reset_runtime()


SLICE = {
    "kind": "Xss",
    "sinkFile": "vulnerabilities/cmdi/home.php",
    "sinkLine": 40,
    "sinkCode": 'echo "<pre>" . $cmd . "</pre>"',
    "sources": [{"file": "vulnerabilities/cmdi/home.php", "line": 33, "code": '$_REQUEST["target"]', "param": "target"}],
    "nodes": [],
}


@pytest.mark.asyncio
async def test_direct_executable(runtime: Any) -> None:
    client = DirectClient(executable_at=0)
    result = await run_direct(SLICE, base_url="http://127.0.0.1/xvwa/vulnerabilities/cmdi/", client=client)
    assert result.verdict == "EXECUTED"
    assert result.notes["attempts"]
    assert result.notes["entry"]["param"] == "target"
    assert "verify_tag" in client.calls


@pytest.mark.asyncio
async def test_direct_reflected_but_inert(runtime: Any) -> None:
    client = DirectClient(executable_at=None)
    result = await run_direct(SLICE, base_url="http://127.0.0.1/xvwa/vulnerabilities/cmdi/", client=client)
    assert result.verdict == "REFLECTED_INERT"
    assert len(result.notes["attempts"]) == min(6, len(_PAYLOADS))


@pytest.mark.asyncio
async def test_direct_not_reflected(runtime: Any) -> None:
    client = DirectClient(found=False)
    result = await run_direct(SLICE, base_url="http://127.0.0.1/xvwa/vulnerabilities/cmdi/", client=client)
    assert result.verdict == "READ_NOT_REFLECTED"


@pytest.mark.asyncio
async def test_direct_page_error(runtime: Any) -> None:
    class Broken(DirectClient):
        def _data(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if tool == "http_request":
                return {"status": 500, "body": "", "content_type": "text/html"}
            return super()._data(tool, arguments)

    result = await run_direct(SLICE, base_url="http://127.0.0.1/xvwa/", client=Broken())
    assert result.verdict == "READ_NOT_REFLECTED"


@pytest.mark.asyncio
async def test_store_keeps_families_apart(runtime: Any) -> None:
    store = runtime_store(runtime)
    store.seed_slices("run-x", [SLICE], order_mode="direct")
    second = {**SLICE, "sinkLine": 77}
    store.seed_slices("run-x", [second], order_mode="second")
    assert store.count_pending("run-x", "direct") == 1
    assert store.count_pending("run-x", "second") == 1
    direct_row = store.next_slice(run_id="run-x", order_mode="direct")
    assert direct_row is not None and direct_row["order_mode"] == "direct"
    second_row = store.next_slice(run_id="run-x", order_mode="second")
    assert second_row is not None and second_row["order_mode"] == "second"


def runtime_store(runtime: Any) -> Any:
    from tia.inf.store import Store

    return Store(runtime.store_path)


def test_pick_family_modes() -> None:
    assert pick_family("direct", 2, 5, 0) == "direct"
    assert pick_family("direct", 0, 5, 0) is None
    assert pick_family("second", 2, 5, 0) == "second"
    assert pick_family("direct-first", 0, 5, 0) == "second"
    assert pick_family("second-first", 2, 0, 0) == "direct"
    assert pick_family("hybrid", 0, 5, 3) == "second"
    assert pick_family("hybrid", 5, 0, 3) == "direct"
    picks = [pick_family("hybrid", 3, 3, index) for index in range(6)]
    assert picks.count("direct") == 3 and picks.count("second") == 3
    assert pick_family("second", 0, 0, 0) is None
