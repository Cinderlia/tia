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

## Accounts

Login credentials are supplied by the operator in a YAML file that never enters
the repository; copy `impl/examples/accounts.example.yaml` to
`impl/var/accounts.yaml` and fill in one entry per account. Each entry carries a
`label`, the application `base_url`, an optional `login_url` (roles may log in on
different pages), `username`, `password` or `password_ref: env:NAME`, the `roles`
it covers and a short `description`.

```bash
uv run tia-agent accounts                # list labels, roles and descriptions
uv run tia-agent login --label site-user  # log in over HTTP, store the cookies
```

`session_bind` without arguments lists the login targets (label, login URL,
roles and description) so the model can choose the identity it needs; passing an
`account_label` binds that one. Passwords are only read at login and are never
written to tool output, evidence or reports. When a bound session expires, the
HTTP-based tools log the same account in again once and replay the request.

## Execution confirmation (optional)

Static verification inspects the returned page and judges whether the payload lands in an
executable context. TIA can additionally load that page in Chrome and record whether the
payload actually executed, which separates "looks executable" from "executed".

Use a browser you already have — just point TIA at it:

```bash
export TIA_CHROME=/usr/bin/google-chrome
```

Or let TIA download its pinned Chrome for Testing build into the project
(`impl/var/browsers/<version>/`, never a global install):

```bash
uv sync --extra browser
uv run tia-agent browser-install   # downloads the pinned version
uv run tia-agent browser-check     # shows which browser will be used
```

`TIA_CHROME` always wins when set. The browser runs headless by default;
`TIA_BROWSER_HEADED=1` opens a window when a display is available. Without a browser the
agents fall back to static judgment and the report says execution was not verified.
