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

## Model (optional)

Planning steps use an OpenAI-compatible endpoint configured in
`config/local/llm.yaml` (see `config/llm.example.yaml`). Besides `base_url`,
`model`, `api_key`/`key_env`, `timeout` and `max_tokens`, a profile can request
thinking:

```yaml
reasoning_effort: low    # off | low | medium | high (provider dependent)
```

No single request shape asks for thinking everywhere, so the client tries the
richest style first (`reasoning_effort` plus `chat_template_kwargs.enable_thinking`),
then `reasoning_effort` alone, then the plain payload, and remembers whichever
one a model accepted. Servers that reject the field with 400/422 fall back
automatically. Check a model and see its latency before relying on it:

```bash
uv run tia-agent llm --probe
```

`TIA_LLM_REASONING_EFFORT=""` disables thinking for one run without editing
the profile.
