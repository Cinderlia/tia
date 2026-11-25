# TIA

**Trace-based Injection Agent** — an agent framework that produces verifiable evidence for
web application data flows: whether a stored value actually reaches a sink and executes, and
whether a remote user can make the application itself write a value into the database.

TIA does not generate exploits and it does not scan for vulnerabilities. It answers two
falsifiable questions with a chain of evidence:

1. **Trigger** — starting from a read point, does the application itself read a value from the
   database and execute it?
2. **Injection** — starting from a legitimate entry point, does the application itself store a
   value in the database, and can that value be read back and executed?

Every conclusion is reported together with the evidence that supports it. TIA never modifies
the target application, never forges sessions, and never writes target columns directly.

## Requirements

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/) for dependency management
- A target web application and a database account that has access only to the target database

## Install

```bash
cd impl
uv sync
```

## Usage

Start the shared capability server over MCP stdio:

```bash
uv run tia-server --profile trigger
```

Run an agent against a slice:

```bash
# Trigger: from a read point to a sink
uv run tia-agent trigger --slice path/to/slice.json --base-url http://127.0.0.1/app/

# Injection: from an entry point to a database write
uv run tia-agent inject --slice path/to/slice.json --base-url http://127.0.0.1/app/

# Main: schedule a queue of slices
uv run tia-agent main --slices path/to/slices.json --base-url http://127.0.0.1/app/
```

Render a Markdown report for a case:

```bash
uv run tia-report <case_id>
```

Database credentials and the target application root are passed through environment variables
(`TIA_DB_HOST`, `TIA_DB_PORT`, `TIA_DB_NAME`, `TIA_DB_USER`, `TIA_DB_PASSWORD`,
`TIA_APP_ROOT`, `TIA_STORE`). Never commit credentials.

## Development

```bash
uv run pytest -q
uv run ruff check src tests
uv run mypy src
```

## Scope

TIA does not provide a web UI, model fine-tuning, a payload generator, or integrations with
IDA or Burp. It never modifies the source code of the target application.
