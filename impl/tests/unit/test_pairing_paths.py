"""Copy paths: recursive pairing over write edges, with verified hops counted free."""

from __future__ import annotations

from tia.orch.pairing import (
    DbOp,
    SliceEntry,
    WriteEdge,
    build_write_index,
    copy_source,
    parse_columns,
    path_stats,
    resolve_paths,
)


def _entry(slice_id: str, ops: list[DbOp]) -> SliceEntry:
    return SliceEntry(slice_id=slice_id, file=f"{slice_id}.php", line=1, kind="", ops=ops)


def _graph() -> dict[tuple[str, str], list[WriteEdge]]:
    sink = _entry("sink", [DbOp("select", "comments", ("comment",))])
    copy = _entry(
        "copy",
        [
            DbOp("select", "drafts", ("body",), sql="select body from drafts"),
            DbOp(
                "insert",
                "comments",
                ("comment",),
                sql="insert into comments (comment) select body from drafts",
            ),
        ],
    )
    seed = _entry(
        "seed",
        [DbOp("insert", "drafts", ("body",), sql="insert into drafts (body) values ('x')")],
    )
    return build_write_index([sink, copy, seed])


def test_copy_source_reads_a_sql_level_copy() -> None:
    op = DbOp(
        "insert",
        "comments",
        ("comment",),
        sql="insert into comments (comment) select body from drafts where id = 1",
    )
    assert copy_source(op) == ("drafts", ("body",))
    assert copy_source(DbOp("insert", "comments", ("comment",), sql="insert into comments (comment) values ('x')")) == ("", ())
    assert parse_columns("a, b as c, count(*)") == ("a", "b")


def test_path_from_entry_to_sink_through_one_copy() -> None:
    paths = resolve_paths(_graph(), "comments", "comment")
    ids = [[edge.entry.slice_id for edge in path] for path in paths]
    assert ["copy", "seed"] in ids
    assert ["copy"] not in ids  # the copy's read column must be fed by an entry


def test_verified_copy_hop_costs_nothing() -> None:
    index = _graph()
    copy = index[("comments", "comment")][0]
    scored, unverified, copies = path_stats([copy], verified=frozenset({copy.edge_id}))
    assert (unverified, copies) == (0, 1)
    assert scored == 80
    unverified_score, unverified_count, _ = path_stats([copy])
    assert unverified_count == 1 and unverified_score == 62


def test_cycle_does_not_loop() -> None:
    a = _entry(
        "a",
        [DbOp("update", "t", ("x",), sql="update t set x = t.y")],
    )
    b = _entry(
        "b",
        [DbOp("update", "t", ("y",), sql="update t set y = t.x")],
    )
    index = build_write_index([a, b])
    paths = resolve_paths(index, "t", "x", max_unverified=2)
    assert paths, "an entry path must still be found"
    for path in paths:
        assert len(path) <= 3


def test_duplicate_edges_collapse_by_slice_and_column() -> None:
    entry = _entry(
        "dup",
        [
            DbOp("insert", "drafts", ("body",), sql="insert into drafts (body) values ('a')"),
            DbOp("insert", "drafts", ("body",), sql="insert into drafts (body) values ('b')"),
        ],
    )
    index = build_write_index([entry])
    assert len(index[("drafts", "body")]) == 1


def test_unverified_hops_are_capped() -> None:
    # t.x <- t.y <- t.z <- t.w; with one unverified hop allowed only the
    # first copy can be crossed.
    a = _entry("a", [DbOp("update", "t", ("x",), sql="update t set x = t.y")])
    b = _entry("b", [DbOp("update", "t", ("y",), sql="update t set y = t.z")])
    c = _entry("c", [DbOp("update", "t", ("z",), sql="update t set z = t.w")])
    index = build_write_index([a, b, c])
    short = resolve_paths(index, "t", "x", max_unverified=1)
    assert all(len(path) == 1 for path in short)


def test_pairing_exposes_copy_paths(tmp_path) -> None:
    from tia.dom.pairing_agent import build_pairing_queue
    from tia.inf.store import Store

    store = Store(tmp_path / "paths.db")
    reads = [
        {
            "kind": "xss",
            "sinkFile": "app/view.php",
            "sinkLine": 61,
            "sinkCode": "select comment from comments",
            "params": [],
        }
    ]
    store.seed_slices("trig-paths", reads)
    for row in store.list_slice_rows("trig-paths"):
        store.archive_slice(str(row["id"]), "EXECUTED")
    proven = store.list_slice_rows("trig-paths", verdicts=("EXECUTED",))

    writes = [
        {
            "kind": "xss",
            "sinkFile": "app/copy.php",
            "sinkLine": 20,
            "sinkCode": "insert into comments (comment) select body from drafts",
            "params": [],
        },
        {
            "kind": "xss",
            "sinkFile": "app/drafts.php",
            "sinkLine": 10,
            "sinkCode": "insert into drafts (body) values (:body)",
            "params": ["body"],
        },
    ]
    result = build_pairing_queue(store, "run-paths", writes, proven)
    assert result.paths, result.notes
    path = result.paths[0]
    assert path["table"] == "comments" and path["column"] == "comment"
    assert path["hops"][0]["is_copy"] is True
    assert path["hops"][-1]["is_copy"] is False
    assert path["unverified_hops"] == 1
