# sqlquery - mysqlnd query and field tracing extension

## What it does

Intercepts mysqli / PDO_MySQL query execution and result-row fetching at the
mysqlnd layer.

- Configuration file: `/tmp/sql_query.json`
- When the configuration is empty, missing or malformed the extension stays
  completely silent: no output is written and the PHP program is unaffected.
- When the **call site** of a query, the **line holding the SQL literal**, or the
  **result-fetch line** matches the configuration, the extension writes the SQL,
  the actual result field metadata and the actual returned rows before the
  request ends:
  - `/tmp/sql/<output>`
- If the target line is reached several times in one request, every call is
  written as its own record (`call_index`).

## Configuration format

```json
{
  "file": "/app/xvwa/vulnerabilities/stored_xss/home.php",
  "line": 56,
  "output": "result_line56.json"
}
```

Accepted field aliases:

- `file` / `path` / `filename`
- `line` / `lineno` / `line_number`
- `output` / `out` / `output_file`

Only the file-name part of `output` is used; every capture lands in `/tmp/sql/`.
A missing `.json` suffix is appended automatically.

### Several targets in one request

A single configuration can observe up to 16 `(file, line)` targets, and one
request matches all of them:

```json
{
  "targets": [
    {"file": "/app/shop/cart.php", "line": 48},
    {"file": "/app/shop/cart.php", "line": 55},
    {"file": "/app/shop/orders.php", "line": 91}
  ],
  "output": "cart.json"
}
```

Each record carries `target_index`, `target_file` and `target_line`; the
top-level object repeats the configured list under `targets` and keeps the
first target in `target_file` / `target_line` for compatibility.

The single `file` + `line` form above remains supported and is treated as a
one-element target list.

## Output format

```json
{
  "target_count": 2,
  "targets": [
    {"file": "...", "line": 48},
    {"file": "...", "line": 56}
  ],
  "target_file": "...",
  "target_line": 48,
  "query_count": 2,
  "queries": [
    {
      "call_index": 1,
      "target_index": 0,
      "sql": "select user,comment,date from comments",
      "kind": "query",
      "matched_at_prepare": false,
      "matched_at_origin": false,
      "matched_at_fetch": false,
      "row_count": 4,
      "affected_rows": 0,
      "execute_time_ms": 0.21,
      "fetch_time_ms": 0.0017,
      "fields": [
        {"name": "user", "org_name": "user", "table": "comments", "db": "xvwa", "type": 253, "length": 120}
      ],
      "rows": [
        ["admin", "Keep posting your comments here ", "10 Aug 2015"]
      ]
    }
  ]
}
```

Write statements have no result set: `fields`/`rows` stay empty and the record
carries `affected_rows` and `last_insert_id` instead.

## Implementation notes

- During `MINIT` the extension wraps mysqlnd methods through their xetters:
  - `mysqlnd_stmt::prepare`
  - `mysqlnd_stmt::execute`
  - `mysqlnd_conn_data::query`
  - `mysqlnd_res::fetch_row`
- Matching walks the whole PHP user-level call stack instead of looking only at
  the innermost frame.
  - For example, WordPress issues its SQL from `wpdb::_do_query()`,
  - while the configured `WP_Post::get_instance()` line 289 sits higher in the
    stack, so matching has to walk upwards.
- Every matched call gets its own `sqlq_ctx`, kept in call order inside
  `sqlq_records`.
  - Repeated `execute()` calls on one prepared statement do not overwrite each
    other.
  - Several queries on one connection are not reduced to the last one.
- `zend_execute_internal` additionally records the call site of
  `PDO::prepare()`.
  - PDO_MySQL enables `ATTR_EMULATE_PREPARES` by default, so `prepare()` itself
    does not touch the database;
  - the real query happens in `PDOStatement::execute()`;
  - recording the prepare site is therefore the only way to match the
    `$stmt = $conn->prepare(...)` line.
- Row values are copied from `result->row_data` after
  `mysqlnd_res::fetch_row()` returns; the PDO/mysqli read cursor is untouched.
- All output is flushed once during `RSHUTDOWN`.

## The three matching modes

1. **Query call site**: while a query executes, the configured file+line is on
   the call stack and matches directly.
   - Suits execution lines such as `$db->query(...)`, `mysqli_query(...)` or
     `$stmt->execute()`.
2. **SQL literal source line**: starting at the configured line the extension
   searches upwards inside the same function/method for the nearest SQL string
   literal and matches the executed SQL against that literal's prefix.
   - Suits lines that only assign the SQL, such as `$sql = "SELECT ...";`.
   - It also covers lines such as `new splitPageResults($sql, ...)` where a
     constructor runs an extra COUNT query: only the main query derived from
     `$sql` is kept and the COUNT query is filtered out.
3. **Result-fetch line**: the query did not match at execution time, but the
   configured line appears on the stack while `fetch_row` / `fetch_assoc` reads
   the result; the query is then attributed retroactively.
   - Suits template lines such as `while ($row = $result->fetch_assoc())`.

`matched_at_origin` in the output means mode 2 selected the query, while
`matched_at_fetch` means mode 3 did. When both are `false` the query matched
directly at its call site.

The literal scan looks at most 200 lines upwards and stops at a `function` /
`class` declaration to avoid cross-function false matches.

## Coverage

Covered:

- PDO emulated prepare / execute (default)
- PDO native prepare / execute
- PDO `query()` / `exec()`
- mysqli `query()` / `real_query()`
- mysqli native prepare plus `bind_result()` / `get_result()`
- mysqli unbuffered queries (`MYSQLI_USE_RESULT`)
- Write statements such as INSERT / UPDATE / DELETE

Not covered / partially supported:

- Statements after the first in `mysqli_multi_query()` are not split apart
- Edge paths such as asynchronous queries, LOAD DATA and local infile

## Building

```bash
docker exec <build-container> bash -lc '
  cd /php-build/php-8.4.25/ext/sqlquery &&
  phpize &&
  ./configure --with-php-config=$(which php-config) &&
  make -j4
'
```

Artifact: `/php-build/php-8.4.25/ext/sqlquery/modules/sqlquery.so`

## Deploying to a test container

```bash
docker cp /home/jmliang/php-build/php-8.4.25/ext/sqlquery/modules/sqlquery.so \
  <test-container>:/usr/local/lib/php/extensions/no-debug-non-zts-20240924/sqlquery.so

docker exec --user root <test-container> bash -lc '
  echo extension=sqlquery.so > /usr/local/etc/php/conf.d/zz-sqlquery.ini
  apache2ctl graceful
'
```

## Verifying

```bash
docker exec --user root <test-container> bash -lc '
  printf "%s" "{\"file\":\"/app/xvwa/vulnerabilities/stored_xss/home.php\",\"line\":56,\"output\":\"result_line56.json\"}" > /tmp/sql_query.json
  curl -s -o /dev/null http://127.0.0.1/xvwa/vulnerabilities/stored_xss/index.php
  cat /tmp/sql/result_line56.json
'
```

## Write-field extraction

Write statements have no result set, so the extension also parses write fields
at the SQL level:

- Text protocol: parses the table, column names, values and WHERE clause of
  `INSERT` / `REPLACE` / `UPDATE`.
- Native prepared statements: reads `stmt->data->param_bind` and substitutes the
  actual parameters for `?` placeholders.

Output fields:

```json
"write": {
  "operation": "INSERT",
  "table": "comments",
  "columns": ["user", "comment", "date"],
  "rows": [["alice", "hello", "30 Oct 2026"]]
}
```

Native prepared statements additionally carry `parameters`. Parsing is
best-effort and covers common forms such as `INSERT ... VALUES`,
`INSERT ... SET`, `UPDATE ... SET` and `DELETE ... WHERE`.

## Debug log

As long as `/tmp/sql_query.json` holds a valid configuration, every request
overwrites:

```text
/tmp/sql/sqlquery_debug.log
```

Example content:

```text
target_file=/app/xvwa/vulnerabilities/stored_xss/home.php
target_line=51
output=/tmp/sql/xvwa_sql_result.json
matched_queries=0
result=no matching query executed in this request
```

- `matched_queries=0`: this request never executed the query matching the
  configured file+line.
- `matched_queries>0`: every call is listed afterwards with its `kind`, `rows`,
  `affected_rows` and SQL.

A typical case: the configuration points at `home.php:51` (the INSERT behind the
comment POST), but the page is opened with GET, so line 51 never runs and no
capture is produced; the debug log states `matched_queries=0` explicitly.
