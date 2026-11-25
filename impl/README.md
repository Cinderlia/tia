# impl

Implementation package for TIA.

```bash
uv sync
uv run pytest -q
uv run ruff check src tests
uv run mypy src
uv run tia-server --profile trigger
```

Entry points:

- `tia-server` — MCP stdio server exposing the capability tools per profile
- `tia-agent` — CLI for the `main`, `trigger` and `inject` agents
- `tia-report` — render a Markdown case report
- `tia` — dispatcher for the three commands above
