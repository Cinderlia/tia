"""Contract tests for the NAVI chain adapter (six chains, graph file per chain)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tia.agent_cli import _load_slices
from tia.dom.pipeline import _read_target
from tia.inf.navi import (
    NaviContractError,
    family_slices,
    load_chain,
    load_navi,
    present_chains,
    split_sink_ref,
)


def _write_chain(root: Path, chain: str, sinks: list[dict[str, object]]) -> Path:
    directory = root / "navi" / chain
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "taint-analysis-graphs.json"
    path.write_text(json.dumps({"sinkSize": len(sinks), "sinks": sinks}), encoding="utf-8")
    return path


def _sink(file: str, line: int, code: str, **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "kind": "Xss",
        "sink": f"{file}:{line}  {code}",
        "params": ["text"],
        "nodes": [
            {"id": "n1", "at": f"{file}:{line}", "code": code},
            {"id": "n2", "at": "includes/actions/write.php:27", "code": "$db->query($sql)"},
        ],
        "edges": [{"from": "n1", "to": "n2", "kind": "data"}],
        "optionalGuards": ["isset($_POST['text'])"],
    }
    payload.update(extra)
    return payload


def test_split_sink_ref_keeps_two_space_contract() -> None:
    file, line, code = split_sink_ref(
        "includes/modules/content/testimonials/templates/tpl_cm_t_list.php:13  echo nl2br($x)"
    )
    assert file == "includes/modules/content/testimonials/templates/tpl_cm_t_list.php"
    assert line == 13
    assert code == "echo nl2br($x)"


def test_split_sink_ref_handles_code_with_colons() -> None:
    file, line, code = split_sink_ref('admin/set_flag.php:14  $db->query("UPDATE t SET s=1")')
    assert file == "admin/set_flag.php"
    assert line == 14
    assert code == '$db->query("UPDATE t SET s=1")'


def test_split_sink_ref_strips_template_wrapper() -> None:
    file, line, _ = split_sink_ref(
        "<template assets/templates/default/faq.twig:30> {{ question|raw }}"
    )
    assert file == "assets/templates/default/faq.twig"
    assert line == 30


def test_load_chain_normalizes_sink_nodes_and_family(tmp_path: Path) -> None:
    _write_chain(tmp_path, "xss-second-order", [_sink("read.php", 13, "echo $row['text']")])
    slices = load_chain(tmp_path, "xss-second-order")
    assert len(slices) == 1
    item = slices[0]
    assert item["family"] == "second"
    assert item["chain"] == "xss-second-order"
    assert item["sink"] == {"file": "read.php", "line": 13, "code": "echo $row['text']"}
    assert item["sinkLine"] == 13
    assert item["nodes"][0]["file"] == "read.php"
    assert item["nodes"][0]["line"] == 13
    assert item["nodes"][0]["code"] == "echo $row['text']"
    assert item["params"] == ["text"]
    assert item["optionalGuards"] == ["isset($_POST['text'])"]


def test_empty_chain_is_legal(tmp_path: Path) -> None:
    _write_chain(tmp_path, "xss-direct", [])
    assert load_chain(tmp_path, "xss-direct") == []
    assert present_chains(tmp_path) == ["xss-direct"]


def test_missing_chain_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(NaviContractError):
        load_chain(tmp_path, "xss-direct")


def test_debug_artifact_is_rejected(tmp_path: Path) -> None:
    debug = tmp_path / "xss-direct" / "joined"
    debug.mkdir(parents=True)
    with pytest.raises(NaviContractError):
        load_chain(tmp_path / "xss-direct", "xss-direct")


def test_load_navi_skips_sql_chains_by_default(tmp_path: Path) -> None:
    _write_chain(tmp_path, "xss-direct", [_sink("a.php", 3, "echo $_GET['x']")])
    _write_chain(tmp_path, "sqlwrite-direct", [_sink("w.php", 9, "$db->query($sql)")])
    grouped = load_navi(tmp_path)
    assert len(grouped["direct"]) == 1
    assert grouped["second"] == []
    assert grouped["sql"] == []


def test_load_navi_includes_sql_when_requested(tmp_path: Path) -> None:
    _write_chain(tmp_path, "sqlwrite-direct", [_sink("w.php", 9, "$db->query($sql)")])
    grouped = load_navi(tmp_path, chains=("sqlwrite-direct",), include_sql=True)
    assert len(grouped["sql"]) == 1


def test_family_slices_maps_write_to_sql(tmp_path: Path) -> None:
    _write_chain(tmp_path, "sqlwrite-direct", [_sink("w.php", 9, "$db->query($sql)")])
    writes = family_slices(tmp_path, "write")
    assert len(writes) == 1
    with pytest.raises(NaviContractError):
        family_slices(tmp_path, "nope")


def test_unknown_chain_name_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(NaviContractError):
        load_navi(tmp_path, chains=("xss-secondorder",))


def test_cli_loads_directory_by_family(tmp_path: Path) -> None:
    _write_chain(tmp_path, "xss-direct", [_sink("a.php", 3, "echo $_GET['x']")])
    _write_chain(tmp_path, "xss-second-order", [_sink("b.php", 13, "echo $row['text']")])
    assert [s["sinkFile"] for s in _load_slices(str(tmp_path), family="direct")] == ["a.php"]
    assert [s["sinkFile"] for s in _load_slices(str(tmp_path), family="second")] == ["b.php"]
    assert len(_load_slices(str(tmp_path))) == 2


def test_cli_still_reads_legacy_files(tmp_path: Path) -> None:
    path = tmp_path / "slices.json"
    path.write_text(json.dumps({"sinks": [_sink("a.php", 3, "echo $x")]}), encoding="utf-8")
    assert len(_load_slices(str(path), family="direct")) == 1


def test_read_target_prefers_trigger_read_line() -> None:
    raw = {
        "sink": {"file": "read.php", "line": 13, "code": "echo $row['text']"},
        "sqlProbe": {"extensionConfig": {"line": "55"}},
    }
    assert _read_target(raw, {"read_line": 61}) == {"file": "read.php", "line": 61}
    assert _read_target(raw, {}) == {"file": "read.php", "line": 55}
    assert _read_target(raw) == {"file": "read.php", "line": 55}


def test_family_roles_are_derived_from_chain_names(tmp_path: Path) -> None:
    """A second-order SQL write chain feeds both ``second`` and ``write``."""
    _write_chain(tmp_path, "xss-direct", [_sink("page.php", 2, "echo $_GET['q']")])
    _write_chain(tmp_path, "xss-second-order", [_sink("read.php", 5, "echo $row")])
    _write_chain(tmp_path, "sqlwrite-second-order", [_sink("write.php", 9, "$db->query($sql)")])
    _write_chain(tmp_path, "sqlwrite-direct", [_sink("direct.php", 3, "$db->query($sql)")])

    second = family_slices(tmp_path, "second")
    write = family_slices(tmp_path, "write")
    direct = family_slices(tmp_path, "direct")

    assert {item["sink"]["line"] for item in second} == {5, 9}
    assert {item["sink"]["line"] for item in write} == {3, 9}
    assert {item["sink"]["line"] for item in direct} == {2}


def test_chain_specs_match_the_contract_table() -> None:
    """The declared table is the contract; every chain has one explicit row."""
    from tia.inf.navi import CHAIN_SPECS, NAVI_CHAINS, chains_for_role

    assert set(CHAIN_SPECS) == set(NAVI_CHAINS)
    assert [spec.kind for spec in CHAIN_SPECS.values()] == [
        "Xss",
        "Xss",
        "SqlInjection",
        "SqlWriteLoose",
        "SqlRead",
        "SqlWriteLoose",
    ]
    assert chains_for_role("second") == ("xss-second-order", "sqlwrite-second-order")
    assert chains_for_role("write") == (
        "sqlwrite-direct",
        "read-to-write",
        "sqlwrite-second-order",
    )
    assert chains_for_role("direct") == ("xss-direct", "sqlread-direct")


def test_unknown_chain_is_a_contract_error(tmp_path: Path) -> None:
    with pytest.raises(NaviContractError):
        load_chain(tmp_path, "xss-third-order")
