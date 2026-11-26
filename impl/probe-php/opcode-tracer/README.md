# opcode_tracer

Directed PHP opcode tracer used by TIA's `trace_run` and `trace_diff` tools.
Derived from the PHP Opcode Tracer project (opcode-level tracing on top of the
Zend VM); TIA adds a per-request JSON config, line/function/depth filters and a
bounded output.

## Build

```bash
phpize
./configure
make
```

Copy `modules/opcode_tracer.so` to the PHP extension directory and enable it
with `extension=opcode_tracer.so`.

## Arm a trace

Write a small flat JSON config to `/tmp/trace_query.json` (override the path
with `TRACE_QUERY_CONFIG`, the output directory with `TRACE_OUTPUT_DIR`):

```json
{
  "file": "/var/www/html/app/home.php",
  "line_from": 40,
  "line_to": 70,
  "function": "",
  "max_depth": 0,
  "max_lines": 20000,
  "output": "trace-1.log"
}
```

The config is read on every request, so one request produces one trace file
under the output directory. The file is truncated when the request starts and
closed when it ends. A trace that hits `max_lines` ends with a `#truncated`
marker.

Fields: `file` is an exact path or a path suffix; `line_from`/`line_to` are
inclusive; `function` keeps frames whose function name contains the value;
`max_depth` keeps frames with at most that many user frames above them (0 means
unlimited); `exclude` is a comma separated opcode list (default skips NOP and
the EXT_* bookkeeping opcodes); `output` must be a plain file name.

Each line looks like:

```
/var/www/html/app/home.php:55 | op=SEND_VAR | pc=118 | depth=0 | func= | o1=CV:comment
```
