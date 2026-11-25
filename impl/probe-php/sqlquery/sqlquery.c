/*
 * sqlquery - mysqlnd query instrumentation extension
 *
 * Reads /tmp/sql_query.json:
 *   {"file":"/abs/path/to/file.php","line":56,"output":"result.json"}
 *
 * When a mysqli/PDO MySQL query is initiated from that exact PHP file+line,
 * the SQL text, result field metadata and the actual returned row values are
 * written to /tmp/sql/<output>.
 *
 * Missing or malformed configuration is silently ignored.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/json/php_json.h"
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_structs.h"
#include "ext/mysqlnd/mysqlnd_ext_plugin.h"
#include "zend_smart_str.h"
#include "zend_hrtime.h"
#include "zend_virtual_cwd.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>

#include "php_sqlquery.h"

#ifndef PHP_SQLQUERY_VERSION
# define PHP_SQLQUERY_VERSION "0.1.0"
#endif

#define SQLQ_CONFIG_PATH "/tmp/sql_query.json"
#define SQLQ_OUTPUT_DIR  "/tmp/sql"

typedef struct {
	bool active;
	char *file;
	char *file_real;
	char *output_path;
	char *origin_sql;
	size_t origin_sql_len;
	zend_long line;
} sqlq_config;

typedef struct {
	char *sql;
	size_t sql_len;

	bool prepared_match;
	bool selected;
	bool executed;
	bool is_ps;
	bool query_stack_match;
	bool matched_at_origin;
	bool matched_at_fetch;

	double execute_ms;
	double fetch_ms;
	uint64_t row_count;
	uint64_t affected_rows;
	uint64_t last_insert_id;
	bool has_affected_rows;

	zval fields;
	bool fields_init;

	zval rows;
	bool rows_init;

	zval params;
	bool params_init;
	unsigned int param_count;

	zval write;
	bool write_init;
} sqlq_ctx;

static sqlq_config cfg;

/* Original mysqlnd method tables, saved before we install wrappers. */
static MYSQLND_CLASS_METHODS_TYPE(mysqlnd_stmt) sqlq_orig_stmt_methods;
static MYSQLND_CLASS_METHODS_TYPE(mysqlnd_stmt) sqlq_our_stmt_methods;
static MYSQLND_CLASS_METHODS_TYPE(mysqlnd_conn_data) sqlq_orig_conn_methods;
static MYSQLND_CLASS_METHODS_TYPE(mysqlnd_conn_data) sqlq_our_conn_methods;
static MYSQLND_CLASS_METHODS_TYPE(mysqlnd_res) sqlq_orig_res_methods;
static MYSQLND_CLASS_METHODS_TYPE(mysqlnd_res) sqlq_our_res_methods;

static bool sqlq_hooked = false;
static bool sqlq_request_active = false;

/* Prepared-statement SQL/state, keyed by MYSQLND_STMT_DATA*. */
typedef struct {
	char *sql;
	size_t sql_len;
	bool prepared_match;
} sqlq_ps_state;

static HashTable sqlq_ps_states;

/* Current execution record per prepared statement / connection.
 * These maps are non-owning; sqlq_records owns every sqlq_ctx. */
static HashTable sqlq_stmt_current;
static HashTable sqlq_conn_current;

/* Every matched query invocation in this request, in call order. */
static HashTable sqlq_records;

/* PDO::prepare() call sites, keyed by PDOStatement object handle.
 * PDO MySQL emulates prepares by default, so the actual mysqlnd query is
 * issued from PDOStatement::execute().  Remembering where the statement was
 * prepared lets a target line such as `$stmt = $conn->prepare(...)` still be
 * matched when that statement is later executed. */
typedef struct {
	char *file;
	zend_long line;
} sqlq_site;

static HashTable sqlq_prepare_sites;

static bool sqlq_in_pdo_execute = false;
static char *sqlq_pdo_execute_file = NULL;
static zend_long sqlq_pdo_execute_line = 0;

static void (*sqlq_orig_execute_internal)(zend_execute_data *execute_data, zval *return_value);

/* {{{ helpers */
static double sqlq_ns_to_ms(uint64_t ns)
{
	return (double)ns / 1000000.0;
}

static char *sqlq_realpath_dup(const char *path)
{
	char resolved[MAXPATHLEN];

	if (path == NULL || *path == '\0') {
		return NULL;
	}
	if (VCWD_REALPATH(path, resolved)) {
		return estrdup(resolved);
	}
	return NULL;
}

static bool sqlq_path_matches(const char *runtime_file)
{
	char *real = NULL;
	bool matched = false;

	if (runtime_file == NULL) {
		return false;
	}
	if (strcmp(runtime_file, cfg.file) == 0) {
		return true;
	}
	if (cfg.file_real == NULL) {
		return false;
	}
	real = sqlq_realpath_dup(runtime_file);
	if (real != NULL) {
		matched = (strcmp(real, cfg.file_real) == 0);
		efree(real);
	}
	return matched;
}

/* Find the immediate userland frame that caused this internal call. */
static bool sqlq_get_user_frame(const char **file, uint32_t *line)
{
	zend_execute_data *ex = EG(current_execute_data);

	while (ex != NULL) {
		if (ex->func != NULL && ex->func->type == ZEND_USER_FUNCTION && ex->opline != NULL) {
			*file = ZSTR_VAL(ex->func->op_array.filename);
			*line = ex->opline->lineno;
			return true;
		}
		ex = ex->prev_execute_data;
	}
	return false;
}

static bool sqlq_frame_matches(void)
{
	zend_execute_data *ex = EG(current_execute_data);

	/* Walk the whole userland stack: a query issued by $wpdb->get_row()
	 * physically happens a few PHP frames deeper, but the line the user
	 * cares about is the frame that initiated the call. */
	while (ex != NULL) {
		if (ex->func != NULL && ex->func->type == ZEND_USER_FUNCTION && ex->opline != NULL) {
			const char *file = ZSTR_VAL(ex->func->op_array.filename);
			uint32_t line = ex->opline->lineno;
			if (line == (uint32_t)cfg.line && sqlq_path_matches(file)) {
				return true;
			}
		}
		ex = ex->prev_execute_data;
	}
	return false;
}

static bool sqlq_origin_matches(const char *sql, size_t len)
{
	size_t i = 0, j = 0;

	if (cfg.origin_sql == NULL || cfg.origin_sql_len == 0) {
		return false;
	}
	while (i < cfg.origin_sql_len) {
		while (i < cfg.origin_sql_len && isspace((unsigned char)cfg.origin_sql[i])) {
			i++;
		}
		if (i >= cfg.origin_sql_len) {
			break;
		}
		while (j < len && isspace((unsigned char)sql[j])) {
			j++;
		}
		if (j >= len) {
			return false;
		}
		if (tolower((unsigned char)cfg.origin_sql[i]) != tolower((unsigned char)sql[j])) {
			return false;
		}
		i++;
		j++;
	}
	return true;
}

static bool sqlq_query_selected(const char *sql, size_t len, bool prepared_match,
		bool *stack_match, bool *origin_match)
{
	bool sm = sqlq_frame_matches();
	bool om = sqlq_origin_matches(sql, len);

	if (stack_match != NULL) {
		*stack_match = sm;
	}
	if (origin_match != NULL) {
		*origin_match = om;
	}
	if (cfg.origin_sql != NULL) {
		return om;
	}
	return prepared_match || sm;
}

static bool sqlq_prepare_site_matches(void)
{
	if (!sqlq_in_pdo_execute || sqlq_pdo_execute_file == NULL) {
		return false;
	}
	return (sqlq_pdo_execute_line == cfg.line) && sqlq_path_matches(sqlq_pdo_execute_file);
}

static void sqlq_ctx_free(sqlq_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->fields_init) {
		zval_ptr_dtor(&ctx->fields);
	}
	if (ctx->rows_init) {
		zval_ptr_dtor(&ctx->rows);
	}
	if (ctx->params_init) {
		zval_ptr_dtor(&ctx->params);
	}
	if (ctx->write_init) {
		zval_ptr_dtor(&ctx->write);
	}
	if (ctx->sql != NULL) {
		efree(ctx->sql);
	}
	efree(ctx);
}

static void sqlq_ctx_dtor(zval *zv)
{
	sqlq_ctx_free((sqlq_ctx *)Z_PTR_P(zv));
}

static void sqlq_ps_state_dtor(zval *zv)
{
	sqlq_ps_state *state = (sqlq_ps_state *)Z_PTR_P(zv);
	if (state != NULL) {
		if (state->sql != NULL) {
			efree(state->sql);
		}
		efree(state);
	}
}

static sqlq_ctx *sqlq_ctx_new(const char *sql, size_t sql_len)
{
	sqlq_ctx *ctx = ecalloc(1, sizeof(sqlq_ctx));

	if (sql != NULL) {
		ctx->sql = estrndup(sql, sql_len);
		ctx->sql_len = sql_len;
	} else {
		ctx->sql = estrdup("");
		ctx->sql_len = 0;
	}
	return ctx;
}

static void sqlq_capture_fields(sqlq_ctx *ctx, MYSQLND_RES *res)
{
	unsigned int i;

	if (ctx->fields_init || res == NULL || res->meta == NULL) {
		return;
	}
	array_init(&ctx->fields);
	ctx->fields_init = true;

	for (i = 0; i < res->meta->field_count; i++) {
		MYSQLND_FIELD *field = &res->meta->fields[i];
		zval f;

		array_init(&f);
		if (field->name != NULL) {
			add_assoc_stringl(&f, "name", field->name, field->name_length);
		} else {
			add_assoc_string(&f, "name", "");
		}
		if (field->org_name != NULL) {
			add_assoc_stringl(&f, "org_name", field->org_name, field->org_name_length);
		}
		if (field->table != NULL) {
			add_assoc_stringl(&f, "table", field->table, field->table_length);
		}
		if (field->org_table != NULL) {
			add_assoc_stringl(&f, "org_table", field->org_table, field->org_table_length);
		}
		if (field->db != NULL) {
			add_assoc_stringl(&f, "db", field->db, field->db_length);
		}
		add_assoc_long(&f, "type", (zend_long)field->type);
		add_assoc_long(&f, "length", (zend_long)field->length);
		add_next_index_zval(&ctx->fields, &f);
	}
}

static void sqlq_capture_current_row(sqlq_ctx *ctx, MYSQLND_RES *res)
{
	unsigned int i;
	unsigned int field_count;
	zval row;

	if (res == NULL || res->row_data == NULL || res->meta == NULL) {
		return;
	}
	field_count = res->meta->field_count;
	if (field_count == 0) {
		return;
	}
	if (!ctx->rows_init) {
		array_init(&ctx->rows);
		ctx->rows_init = true;
	}

	array_init(&row);
	for (i = 0; i < field_count; i++) {
		zval *value = &res->row_data[i];
		if (Z_TYPE_P(value) == IS_UNDEF) {
			add_next_index_null(&row);
		} else {
			zval copy;
			ZVAL_COPY(&copy, value);
			add_next_index_zval(&row, &copy);
		}
	}
	add_next_index_zval(&ctx->rows, &row);
	ctx->row_count++;
}
/* }}} */

/* {{{ config loading */
static bool sqlq_read_file(const char *path, char **data, size_t *len)
{
	FILE *fp;
	long size;
	char *buf;
	size_t got;

	fp = fopen(path, "rb");
	if (fp == NULL) {
		return false;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return false;
	}
	size = ftell(fp);
	if (size < 0 || size > 1024 * 1024) {
		fclose(fp);
		return false;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return false;
	}
	buf = emalloc((size_t)size + 1);
	got = fread(buf, 1, (size_t)size, fp);
	fclose(fp);
	buf[got] = '\0';
	*data = buf;
	*len = got;
	return true;
}

static zval *sqlq_array_find(zval *array, const char *key, size_t key_len)
{
	if (array == NULL || Z_TYPE_P(array) != IS_ARRAY) {
		return NULL;
	}
	return zend_hash_str_find(Z_ARRVAL_P(array), key, key_len);
}

static bool sqlq_has_word(const char *s, size_t len, const char *word)
{
	size_t wl = strlen(word);
	size_t i;

	for (i = 0; i + wl <= len; i++) {
		bool left_ok = (i == 0) || !(isalnum((unsigned char)s[i - 1]) || s[i - 1] == '_');
		bool right_ok = (i + wl == len) || !(isalnum((unsigned char)s[i + wl]) || s[i + wl] == '_');
		if (left_ok && right_ok && strncasecmp(s + i, word, wl) == 0) {
			return true;
		}
	}
	return false;
}

static bool sqlq_starts_with_sql_keyword(const char *s, size_t len)
{
	static const char *keywords[] = { "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE" };
	size_t i;

	while (len > 0 && isspace((unsigned char)*s)) {
		s++;
		len--;
	}
	for (i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
		size_t wl = strlen(keywords[i]);
		if (len >= wl && strncasecmp(s, keywords[i], wl) == 0) {
			if (len == wl || !(isalnum((unsigned char)s[wl]) || s[wl] == '_')) {
				return true;
			}
		}
	}
	return false;
}

static char *sqlq_extract_sql_literal(const char *s, size_t len, size_t *out_len)
{
	size_t i = 0;

	while (i < len) {
		char quote;
		size_t j;
		bool has_dollar = false;
		bool closed = false;
		smart_str buf = {0};

		if (s[i] != '\'' && s[i] != '"') {
			i++;
			continue;
		}
		quote = s[i];
		j = i + 1;
		while (j < len) {
			char c = s[j];
			if (c == '\\' && j + 1 < len) {
				j++;
				smart_str_appendc(&buf, s[j]);
				j++;
				continue;
			}
			if (c == quote) {
				if (j + 1 < len && s[j + 1] == quote) {
					smart_str_appendc(&buf, quote);
					j += 2;
					continue;
				}
				closed = true;
				j++;
				break;
			}
			if (quote == '"' && c == '$') {
				has_dollar = true;
			}
			smart_str_appendc(&buf, c);
			j++;
		}
		i = j;

		if (!closed || has_dollar) {
			smart_str_free(&buf);
			continue;
		}
		smart_str_0(&buf);
		if (buf.s != NULL) {
			const char *lit = ZSTR_VAL(buf.s);
			size_t lit_len = ZSTR_LEN(buf.s);
			size_t a = 0, b = lit_len, end;

			while (a < b && isspace((unsigned char)lit[a])) {
				a++;
			}
			while (b > a && isspace((unsigned char)lit[b - 1])) {
				b--;
			}
			if (b > a && sqlq_starts_with_sql_keyword(lit + a, b - a)) {
				end = a;
				while (end < b) {
					if (lit[end] == '?') {
						break;
					}
					if (lit[end] == ':' && end + 1 < b &&
							(isalpha((unsigned char)lit[end + 1]) || lit[end + 1] == '_')) {
						break;
					}
					end++;
				}
				while (end > a && isspace((unsigned char)lit[end - 1])) {
					end--;
				}
				if (end > a + 7) {
					char *out = estrndup(lit + a, end - a);
					*out_len = end - a;
					smart_str_free(&buf);
					return out;
				}
			}
		}
		smart_str_free(&buf);
	}
	return NULL;
}

static void sqlq_load_origin_sql(void)
{
	char *data = NULL;
	size_t len = 0;
	size_t *starts = NULL;
	size_t *ends = NULL;
	size_t nlines = 1;
	size_t line = 0;
	size_t start = 0;
	size_t i;
	zend_long target, min, idx;

	if (cfg.file == NULL || cfg.line <= 0) {
		return;
	}
	if (!sqlq_read_file(cfg.file, &data, &len)) {
		return;
	}
	for (i = 0; i < len; i++) {
		if (data[i] == '\n') {
			nlines++;
		}
	}
	starts = emalloc(nlines * sizeof(size_t));
	ends = emalloc(nlines * sizeof(size_t));
	for (i = 0; i <= len; i++) {
		if (i == len || data[i] == '\n') {
			starts[line] = start;
			ends[line] = i;
			line++;
			start = i + 1;
		}
	}
	if ((size_t)cfg.line > line) {
		goto done;
	}

	target = (zend_long)cfg.line - 1;
	min = target > 200 ? target - 200 : 0;
	for (idx = target; idx >= min; idx--) {
		size_t idx_u = (size_t)idx;
		size_t lstart = starts[idx_u];
		size_t lend = ends[idx_u];
		char *lit;
		size_t lit_len = 0;

		if (idx != target &&
				(sqlq_has_word(data + lstart, lend - lstart, "function") ||
				 sqlq_has_word(data + lstart, lend - lstart, "class"))) {
			break;
		}
		lit = sqlq_extract_sql_literal(data + lstart, lend - lstart, &lit_len);
		if (lit != NULL) {
			cfg.origin_sql = lit;
			cfg.origin_sql_len = lit_len;
			break;
		}
	}

done:
	if (starts != NULL) {
		efree(starts);
	}
	if (ends != NULL) {
		efree(ends);
	}
	efree(data);
}

static void sqlq_reset_config(void)
{
	if (cfg.file != NULL) {
		efree(cfg.file);
	}
	if (cfg.file_real != NULL) {
		efree(cfg.file_real);
	}
	if (cfg.output_path != NULL) {
		efree(cfg.output_path);
	}
	if (cfg.origin_sql != NULL) {
		efree(cfg.origin_sql);
	}
	memset(&cfg, 0, sizeof(cfg));
}

static bool sqlq_load_config(void)
{
	char *raw = NULL;
	size_t raw_len = 0;
	zval root;
	zval *zfile;
	zval *zline;
	zval *zoutput;
	const char *output_name = "sql_result.json";
	char *output_base = NULL;
	size_t output_len;

	sqlq_reset_config();

	if (!sqlq_read_file(SQLQ_CONFIG_PATH, &raw, &raw_len)) {
		return false;
	}
	if (raw_len == 0) {
		efree(raw);
		return false;
	}

	ZVAL_UNDEF(&root);
	if (php_json_decode_ex(&root, raw, raw_len, PHP_JSON_OBJECT_AS_ARRAY, 512) != SUCCESS) {
		efree(raw);
		return false;
	}
	efree(raw);

	if (Z_TYPE(root) != IS_ARRAY) {
		zval_ptr_dtor(&root);
		return false;
	}

	zfile = sqlq_array_find(&root, "file", sizeof("file") - 1);
	if (zfile == NULL) {
		zfile = sqlq_array_find(&root, "path", sizeof("path") - 1);
	}
	if (zfile == NULL) {
		zfile = sqlq_array_find(&root, "filename", sizeof("filename") - 1);
	}
	zline = sqlq_array_find(&root, "line", sizeof("line") - 1);
	if (zline == NULL) {
		zline = sqlq_array_find(&root, "lineno", sizeof("lineno") - 1);
	}
	if (zline == NULL) {
		zline = sqlq_array_find(&root, "line_number", sizeof("line_number") - 1);
	}
	zoutput = sqlq_array_find(&root, "output", sizeof("output") - 1);
	if (zoutput == NULL) {
		zoutput = sqlq_array_find(&root, "out", sizeof("out") - 1);
	}
	if (zoutput == NULL) {
		zoutput = sqlq_array_find(&root, "output_file", sizeof("output_file") - 1);
	}

	if (zfile == NULL || Z_TYPE_P(zfile) != IS_STRING || Z_STRLEN_P(zfile) == 0) {
		zval_ptr_dtor(&root);
		return false;
	}
	if (zline == NULL || (Z_TYPE_P(zline) != IS_LONG && Z_TYPE_P(zline) != IS_STRING)) {
		zval_ptr_dtor(&root);
		return false;
	}

	cfg.file = estrndup(Z_STRVAL_P(zfile), Z_STRLEN_P(zfile));
	cfg.line = zval_get_long(zline);
	if (cfg.line <= 0) {
		sqlq_reset_config();
		zval_ptr_dtor(&root);
		return false;
	}
	cfg.file_real = sqlq_realpath_dup(cfg.file);

	if (zoutput != NULL && Z_TYPE_P(zoutput) == IS_STRING && Z_STRLEN_P(zoutput) > 0) {
		output_name = Z_STRVAL_P(zoutput);
	}
	output_len = strlen(output_name);
	output_base = estrndup(output_name, output_len);
	/* Keep the output inside /tmp/sql: strip any directory component. */
	{
		char *slash = strrchr(output_base, '/');
		char *bslash = strrchr(output_base, '\\');
		if (slash != NULL || bslash != NULL) {
			char *last = slash;
			if (bslash != NULL && (last == NULL || bslash > last)) {
				last = bslash;
			}
			memmove(output_base, last + 1, strlen(last + 1) + 1);
		}
	}
	output_len = strlen(output_base);
	if (output_len == 0) {
		efree(output_base);
		output_base = estrdup("sql_result.json");
		output_len = strlen(output_base);
	}
	if (output_len < 5 || strcmp(output_base + output_len - 5, ".json") != 0) {
		char *with_ext = emalloc(output_len + 6);
		memcpy(with_ext, output_base, output_len);
		memcpy(with_ext + output_len, ".json", 6);
		efree(output_base);
		output_base = with_ext;
	}
	cfg.output_path = emalloc(strlen(SQLQ_OUTPUT_DIR) + 1 + strlen(output_base) + 1);
	sprintf(cfg.output_path, "%s/%s", SQLQ_OUTPUT_DIR, output_base);
	efree(output_base);

	zval_ptr_dtor(&root);
	cfg.active = true;

	/* Make sure the output directory exists; failures stay silent. */
	if (mkdir(SQLQ_OUTPUT_DIR, 0777) != 0 && errno != EEXIST) {
		/* Nothing to do: writing will simply fail later. */
	}
	sqlq_load_origin_sql();
	return true;
}
/* }}} */

/* {{{ write-statement parsing (best effort) */
typedef struct {
	const char *s;
	size_t len;
	zval *params;
	unsigned int param_count;
	unsigned int param_index;
} sqlq_parser;

#define SQLQ_NPOS ((size_t)-1)

static bool sqlq_is_word_char(char c)
{
	return isalnum((unsigned char)c) || c == '_' || c == '$';
}

static void sqlq_skip_ws(const char *s, size_t len, size_t *pos)
{
	while (*pos < len && isspace((unsigned char)s[*pos])) {
		(*pos)++;
	}
}

static bool sqlq_match_word(const char *s, size_t len, size_t pos, const char *word, size_t *end)
{
	size_t wl = strlen(word);
	size_t i;

	if (pos + wl > len) {
		return false;
	}
	for (i = 0; i < wl; i++) {
		if (tolower((unsigned char)s[pos + i]) != tolower((unsigned char)word[i])) {
			return false;
		}
	}
	if (pos > 0 && sqlq_is_word_char(s[pos - 1])) {
		return false;
	}
	if (pos + wl < len && sqlq_is_word_char(s[pos + wl])) {
		return false;
	}
	if (end != NULL) {
		*end = pos + wl;
	}
	return true;
}

static size_t sqlq_find_keyword(const char *s, size_t len, size_t start, const char *kw)
{
	bool sq = false, dq = false, bt = false;
	size_t i;

	for (i = start; i < len; i++) {
		char c = s[i];
		if (sq) {
			if (c == '\\' && i + 1 < len) { i++; }
			else if (c == '\'') {
				if (i + 1 < len && s[i + 1] == '\'') { i++; }
				else { sq = false; }
			}
			continue;
		}
		if (dq) {
			if (c == '\\' && i + 1 < len) { i++; }
			else if (c == '"') {
				if (i + 1 < len && s[i + 1] == '"') { i++; }
				else { dq = false; }
			}
			continue;
		}
		if (bt) {
			if (c == '`') {
				if (i + 1 < len && s[i + 1] == '`') { i++; }
				else { bt = false; }
			}
			continue;
		}
		if (c == '\'') { sq = true; continue; }
		if (c == '"') { dq = true; continue; }
		if (c == '`') { bt = true; continue; }
		if (sqlq_match_word(s, len, i, kw, NULL)) {
			return i;
		}
	}
	return SQLQ_NPOS;
}

static bool sqlq_match_paren(const char *s, size_t len, size_t open, size_t *close)
{
	bool sq = false, dq = false, bt = false;
	int depth = 0;
	size_t i;

	for (i = open; i < len; i++) {
		char c = s[i];
		if (sq) {
			if (c == '\\' && i + 1 < len) { i++; }
			else if (c == '\'') {
				if (i + 1 < len && s[i + 1] == '\'') { i++; }
				else { sq = false; }
			}
			continue;
		}
		if (dq) {
			if (c == '\\' && i + 1 < len) { i++; }
			else if (c == '"') {
				if (i + 1 < len && s[i + 1] == '"') { i++; }
				else { dq = false; }
			}
			continue;
		}
		if (bt) {
			if (c == '`') {
				if (i + 1 < len && s[i + 1] == '`') { i++; }
				else { bt = false; }
			}
			continue;
		}
		if (c == '\'') { sq = true; continue; }
		if (c == '"') { dq = true; continue; }
		if (c == '`') { bt = true; continue; }
		if (c == '(') { depth++; }
		else if (c == ')') {
			depth--;
			if (depth == 0) { *close = i; return true; }
		}
	}
	return false;
}

static size_t sqlq_find_comma(const char *s, size_t len, size_t start, size_t end)
{
	bool sq = false, dq = false, bt = false;
	int depth = 0;
	size_t i;

	for (i = start; i < end; i++) {
		char c = s[i];
		if (sq) {
			if (c == '\\' && i + 1 < end) { i++; }
			else if (c == '\'') {
				if (i + 1 < end && s[i + 1] == '\'') { i++; }
				else { sq = false; }
			}
			continue;
		}
		if (dq) {
			if (c == '\\' && i + 1 < end) { i++; }
			else if (c == '"') {
				if (i + 1 < end && s[i + 1] == '"') { i++; }
				else { dq = false; }
			}
			continue;
		}
		if (bt) {
			if (c == '`') {
				if (i + 1 < end && s[i + 1] == '`') { i++; }
				else { bt = false; }
			}
			continue;
		}
		if (c == '\'') { sq = true; continue; }
		if (c == '"') { dq = true; continue; }
		if (c == '`') { bt = true; continue; }
		if (c == '(') { depth++; }
		else if (c == ')') { depth--; }
		else if (c == ',' && depth == 0) { return i; }
	}
	return end;
}

static size_t sqlq_find_char(const char *s, size_t len, size_t start, size_t end, char target)
{
	bool sq = false, dq = false, bt = false;
	int depth = 0;
	size_t i;

	for (i = start; i < end; i++) {
		char c = s[i];
		if (sq) {
			if (c == '\\' && i + 1 < end) { i++; }
			else if (c == '\'') {
				if (i + 1 < end && s[i + 1] == '\'') { i++; }
				else { sq = false; }
			}
			continue;
		}
		if (dq) {
			if (c == '\\' && i + 1 < end) { i++; }
			else if (c == '"') {
				if (i + 1 < end && s[i + 1] == '"') { i++; }
				else { dq = false; }
			}
			continue;
		}
		if (bt) {
			if (c == '`') {
				if (i + 1 < end && s[i + 1] == '`') { i++; }
				else { bt = false; }
			}
			continue;
		}
		if (c == '\'') { sq = true; continue; }
		if (c == '"') { dq = true; continue; }
		if (c == '`') { bt = true; continue; }
		if (c == '(') { depth++; }
		else if (c == ')') { depth--; }
		else if (c == target && depth == 0) { return i; }
	}
	return SQLQ_NPOS;
}

static void sqlq_trim(const char *s, size_t *start, size_t *end)
{
	while (*start < *end && isspace((unsigned char)s[*start])) {
		(*start)++;
	}
	while (*end > *start && isspace((unsigned char)s[*end - 1])) {
		(*end)--;
	}
}

static char *sqlq_ident_dup(const char *s, size_t start, size_t end)
{
	char *out;
	size_t i, n = 0;
	size_t last_dot = SQLQ_NPOS;

	sqlq_trim(s, &start, &end);
	out = emalloc(end - start + 1);
	for (i = start; i < end; i++) {
		if (s[i] == '`') {
			continue;
		}
		if (s[i] == '.') {
			last_dot = n;
		}
		out[n++] = s[i];
	}
	out[n] = '\0';
	if (last_dot != SQLQ_NPOS && last_dot + 1 < n) {
		memmove(out, out + last_dot + 1, n - last_dot);
	}
	return out;
}

static char *sqlq_parse_table(const char *s, size_t len, size_t *pos)
{
	size_t start = *pos;
	bool bt = false;

	while (*pos < len) {
		char c = s[*pos];
		if (c == '`') { bt = !bt; }
		else if (!bt && (isspace((unsigned char)c) || c == '(' || c == ';')) { break; }
		(*pos)++;
	}
	if (*pos == start) {
		return NULL;
	}
	return sqlq_ident_dup(s, start, *pos);
}

static void sqlq_add_quoted_value(zval *row, const char *s, size_t start, size_t end)
{
	char quote;
	size_t i, j;
	smart_str out = {0};

	sqlq_trim(s, &start, &end);
	if (end - start < 2) {
		add_next_index_stringl(row, s + start, end - start);
		return;
	}
	quote = s[start];
	i = start + 1;
	j = end - 1;
	while (i < j) {
		char c = s[i];
		if (c == '\\' && i + 1 < j) {
			i++;
			switch (s[i]) {
				case '0': c = '\0'; break;
				case 'b': c = '\b'; break;
				case 'n': c = '\n'; break;
				case 'r': c = '\r'; break;
				case 't': c = '\t'; break;
				case 'Z': c = 0x1a; break;
				default: c = s[i]; break;
			}
			smart_str_appendc(&out, c);
			i++;
			continue;
		}
		if (c == quote && i + 1 < j && s[i + 1] == quote) {
			smart_str_appendc(&out, quote);
			i += 2;
			continue;
		}
		smart_str_appendc(&out, c);
		i++;
	}
	smart_str_0(&out);
	if (out.s != NULL) {
		add_next_index_stringl(row, ZSTR_VAL(out.s), ZSTR_LEN(out.s));
	} else {
		add_next_index_string(row, "");
	}
	smart_str_free(&out);
}

static void sqlq_add_value(zval *row, sqlq_parser *p, size_t start, size_t end)
{
	const char *s = p->s;
	zend_long lval;
	double dval;
	char *tmp;

	sqlq_trim(s, &start, &end);
	if (start >= end) {
		add_next_index_string(row, "");
		return;
	}

	if (end - start == 1 && s[start] == '?') {
		if (p->params != NULL && p->param_index < p->param_count) {
			zval *param = zend_hash_index_find(Z_ARRVAL_P(p->params), p->param_index);
			p->param_index++;
			if (param != NULL) {
				zval copy;
				ZVAL_COPY_DEREF(&copy, param);
				add_next_index_zval(row, &copy);
				return;
			}
		}
		add_next_index_null(row);
		return;
	}

	if (sqlq_match_word(s, end, start, "NULL", NULL)) {
		add_next_index_null(row);
		return;
	}
	if (s[start] == '\'' || s[start] == '"') {
		sqlq_add_quoted_value(row, s, start, end);
		return;
	}

	tmp = estrndup(s + start, end - start);
	if (is_numeric_string(tmp, end - start, &lval, &dval, 0) == IS_LONG) {
		add_next_index_long(row, lval);
	} else if (is_numeric_string(tmp, end - start, &lval, &dval, 0) == IS_DOUBLE) {
		add_next_index_double(row, dval);
	} else {
		add_next_index_string(row, tmp);
	}
	efree(tmp);
}

static void sqlq_parse_column_list(zval *cols, const char *s, size_t len, size_t start, size_t end)
{
	size_t pos = start;

	while (pos < end) {
		size_t comma = sqlq_find_comma(s, len, pos, end);
		char *id = sqlq_ident_dup(s, pos, comma);
		if (id[0] != '\0') {
			add_next_index_string(cols, id);
		}
		efree(id);
		if (comma >= end) {
			break;
		}
		pos = comma + 1;
	}
}

static void sqlq_parse_assignments(zval *cols, zval *row, sqlq_parser *p, size_t start, size_t end)
{
	size_t pos = start;

	while (pos < end) {
		size_t comma = sqlq_find_comma(p->s, p->len, pos, end);
		size_t eq = sqlq_find_char(p->s, p->len, pos, comma, '=');
		char *id;
		if (eq == SQLQ_NPOS) {
			break;
		}
		id = sqlq_ident_dup(p->s, pos, eq);
		if (id[0] != '\0') {
			add_next_index_string(cols, id);
		}
		efree(id);
		sqlq_add_value(row, p, eq + 1, comma);
		if (comma >= end) {
			break;
		}
		pos = comma + 1;
	}
}

static void sqlq_parse_write(sqlq_ctx *ctx)
{
	const char *s = ctx->sql;
	size_t len = ctx->sql_len;
	size_t pos = 0, end = 0;
	sqlq_parser p;
	char operation[16];
	char *table = NULL;
	zval cols, rows, where_val;
	bool have_where = false;
	bool is_insert = false;

	if (s == NULL || len == 0) {
		return;
	}
	memset(operation, 0, sizeof(operation));
	p.s = s;
	p.len = len;
	p.params = ctx->params_init ? &ctx->params : NULL;
	p.param_count = ctx->param_count;
	p.param_index = 0;

	sqlq_skip_ws(s, len, &pos);
	if (sqlq_match_word(s, len, pos, "INSERT", &end)) {
		strcpy(operation, "INSERT");
		is_insert = true;
		pos = end;
		sqlq_skip_ws(s, len, &pos);
		if (sqlq_match_word(s, len, pos, "IGNORE", &end) ||
			sqlq_match_word(s, len, pos, "LOW_PRIORITY", &end) ||
			sqlq_match_word(s, len, pos, "DELAYED", &end)) {
			pos = end;
			sqlq_skip_ws(s, len, &pos);
		}
		if (sqlq_match_word(s, len, pos, "INTO", &end)) {
			pos = end;
			sqlq_skip_ws(s, len, &pos);
		}
	} else if (sqlq_match_word(s, len, pos, "REPLACE", &end)) {
		strcpy(operation, "REPLACE");
		is_insert = true;
		pos = end;
		sqlq_skip_ws(s, len, &pos);
		if (sqlq_match_word(s, len, pos, "INTO", &end)) {
			pos = end;
			sqlq_skip_ws(s, len, &pos);
		}
	} else if (sqlq_match_word(s, len, pos, "UPDATE", &end)) {
		strcpy(operation, "UPDATE");
		pos = end;
		sqlq_skip_ws(s, len, &pos);
		if (sqlq_match_word(s, len, pos, "LOW_PRIORITY", &end) ||
			sqlq_match_word(s, len, pos, "IGNORE", &end)) {
			pos = end;
			sqlq_skip_ws(s, len, &pos);
		}
	} else if (sqlq_match_word(s, len, pos, "DELETE", &end)) {
		strcpy(operation, "DELETE");
		pos = end;
		sqlq_skip_ws(s, len, &pos);
		if (sqlq_match_word(s, len, pos, "LOW_PRIORITY", &end) ||
			sqlq_match_word(s, len, pos, "QUICK", &end) ||
			sqlq_match_word(s, len, pos, "IGNORE", &end)) {
			pos = end;
			sqlq_skip_ws(s, len, &pos);
		}
		if (sqlq_match_word(s, len, pos, "FROM", &end)) {
			pos = end;
			sqlq_skip_ws(s, len, &pos);
		}
	} else {
		return;
	}

	if (operation[0] == '\0') {
		return;
	}

	table = sqlq_parse_table(s, len, &pos);
	sqlq_skip_ws(s, len, &pos);

	array_init(&cols);
	array_init(&rows);
	ZVAL_UNDEF(&where_val);

	if (is_insert) {
		if (pos < len && s[pos] == '(') {
			size_t close;
			if (sqlq_match_paren(s, len, pos, &close)) {
				sqlq_parse_column_list(&cols, s, len, pos + 1, close);
				pos = close + 1;
				sqlq_skip_ws(s, len, &pos);
			}
		}

		if (sqlq_match_word(s, len, pos, "VALUES", &end) ||
			sqlq_match_word(s, len, pos, "VALUE", &end)) {
			pos = end;
			sqlq_skip_ws(s, len, &pos);
			while (pos < len) {
				size_t close;
				zval row;
				size_t vstart, vend, comma;
				if (s[pos] != '(') {
					break;
				}
				if (!sqlq_match_paren(s, len, pos, &close)) {
					break;
				}
				array_init(&row);
				vstart = pos + 1;
				vend = close;
				while (vstart < vend) {
					comma = sqlq_find_comma(s, len, vstart, vend);
					sqlq_add_value(&row, &p, vstart, comma);
					if (comma >= vend) {
						break;
					}
					vstart = comma + 1;
				}
				add_next_index_zval(&rows, &row);
				pos = close + 1;
				sqlq_skip_ws(s, len, &pos);
				if (pos < len && s[pos] == ',') {
					pos++;
					sqlq_skip_ws(s, len, &pos);
					continue;
				}
				break;
			}
		} else if (sqlq_match_word(s, len, pos, "SET", &end)) {
			size_t set_end = len;
			size_t dup = sqlq_find_keyword(s, len, end, "ON");
			zval row;
			if (dup != SQLQ_NPOS) {
				set_end = dup;
			}
			array_init(&row);
			sqlq_parse_assignments(&cols, &row, &p, end, set_end);
			add_next_index_zval(&rows, &row);
		}
	} else if (strcmp(operation, "UPDATE") == 0) {
		size_t set_pos = sqlq_find_keyword(s, len, pos, "SET");
		size_t set_end = len;
		size_t where_pos;
		zval row;
		if (set_pos == SQLQ_NPOS) {
			goto done;
		}
		where_pos = sqlq_find_keyword(s, len, set_pos + 3, "WHERE");
		if (where_pos != SQLQ_NPOS) {
			set_end = where_pos;
			{
				size_t wstart = where_pos + 5;
				size_t wend = len;
				sqlq_trim(s, &wstart, &wend);
				ZVAL_STRINGL(&where_val, s + wstart, wend - wstart);
				have_where = true;
			}
		}
		array_init(&row);
		sqlq_parse_assignments(&cols, &row, &p, set_pos + 3, set_end);
		add_next_index_zval(&rows, &row);
	} else if (strcmp(operation, "DELETE") == 0) {
		size_t where_pos = sqlq_find_keyword(s, len, pos, "WHERE");
		if (where_pos != SQLQ_NPOS) {
			size_t wstart = where_pos + 5;
			size_t wend = len;
			sqlq_trim(s, &wstart, &wend);
			ZVAL_STRINGL(&where_val, s + wstart, wend - wstart);
			have_where = true;
		}
	}

done:
	array_init(&ctx->write);
	add_assoc_string(&ctx->write, "operation", operation);
	if (table != NULL && table[0] != '\0') {
		add_assoc_string(&ctx->write, "table", table);
	}
	add_assoc_zval(&ctx->write, "columns", &cols);
	add_assoc_zval(&ctx->write, "rows", &rows);
	if (have_where) {
		add_assoc_zval(&ctx->write, "where", &where_val);
	} else {
		zval_ptr_dtor(&where_val);
	}
	if (ctx->params_init) {
		zval params_copy;
		ZVAL_COPY(&params_copy, &ctx->params);
		add_assoc_zval(&ctx->write, "parameters", &params_copy);
	}
	ctx->write_init = true;

	if (table != NULL) {
		efree(table);
	}
}

static void sqlq_capture_params(sqlq_ctx *ctx, MYSQLND_STMT *const s)
{
	unsigned int i;

	if (s == NULL || s->data == NULL || s->data->param_count == 0 || s->data->param_bind == NULL) {
		return;
	}
	array_init(&ctx->params);
	ctx->params_init = true;
	ctx->param_count = s->data->param_count;
	for (i = 0; i < s->data->param_count; i++) {
		if (!Z_ISUNDEF(s->data->param_bind[i].zv)) {
			zval copy;
			ZVAL_COPY_DEREF(&copy, &s->data->param_bind[i].zv);
			add_next_index_zval(&ctx->params, &copy);
		} else {
			add_next_index_null(&ctx->params);
		}
	}
}
/* }}} */

/* {{{ capture/flush */
static void sqlq_add_ctx_to_queries(zval *queries, sqlq_ctx *ctx, uint32_t call_index)
{
	zval q;
	zval fields;
	zval rows;

	if (ctx == NULL || !ctx->selected || !ctx->executed) {
		return;
	}

	array_init(&q);
	add_assoc_long(&q, "call_index", (zend_long)call_index);
	add_assoc_stringl(&q, "sql", ctx->sql != NULL ? ctx->sql : "", ctx->sql_len);
	add_assoc_string(&q, "kind", ctx->is_ps ? "prepared" : "query");
	add_assoc_bool(&q, "matched_at_prepare", ctx->prepared_match);
	add_assoc_bool(&q, "matched_at_origin", ctx->matched_at_origin);
	add_assoc_bool(&q, "matched_at_fetch", ctx->matched_at_fetch);
	add_assoc_long(&q, "row_count", (zend_long)ctx->row_count);
	if (ctx->has_affected_rows) {
		add_assoc_long(&q, "affected_rows", (zend_long)ctx->affected_rows);
	}
	if (ctx->last_insert_id > 0) {
		add_assoc_long(&q, "last_insert_id", (zend_long)ctx->last_insert_id);
	}
	if (ctx->write_init) {
		zval write_copy;
		ZVAL_COPY(&write_copy, &ctx->write);
		add_assoc_zval(&q, "write", &write_copy);
	}
	add_assoc_double(&q, "execute_time_ms", ctx->execute_ms);
	add_assoc_double(&q, "fetch_time_ms", ctx->fetch_ms);

	if (ctx->fields_init) {
		ZVAL_COPY(&fields, &ctx->fields);
	} else {
		array_init(&fields);
	}
	add_assoc_zval(&q, "fields", &fields);

	if (ctx->rows_init) {
		ZVAL_COPY(&rows, &ctx->rows);
	} else {
		array_init(&rows);
	}
	add_assoc_zval(&q, "rows", &rows);

	add_next_index_zval(queries, &q);
}

static uint32_t sqlq_flush_output(void)
{
	zval root;
	zval queries;
	zval *zv;
	uint32_t count = 0;
	uint32_t index = 0;
	smart_str encoded = {0};

	ZVAL_UNDEF(&root);
	array_init(&root);
	array_init(&queries);

	ZEND_HASH_MAP_FOREACH_VAL(&sqlq_records, zv) {
		sqlq_ctx *ctx = (sqlq_ctx *)Z_PTR_P(zv);
		if (ctx != NULL && ctx->selected && ctx->executed) {
			index++;
			sqlq_add_ctx_to_queries(&queries, ctx, index);
		}
	} ZEND_HASH_FOREACH_END();

	count = zend_hash_num_elements(Z_ARRVAL(queries));
	if (count == 0) {
		zval_ptr_dtor(&queries);
		zval_ptr_dtor(&root);
		return 0;
	}

	add_assoc_string(&root, "target_file", cfg.file != NULL ? cfg.file : "");
	add_assoc_long(&root, "target_line", cfg.line);
	add_assoc_long(&root, "query_count", (zend_long)count);
	add_assoc_zval(&root, "queries", &queries);

	if (php_json_encode_ex(&encoded, &root,
			PHP_JSON_UNESCAPED_UNICODE | PHP_JSON_UNESCAPED_SLASHES |
			PHP_JSON_PRETTY_PRINT | PHP_JSON_INVALID_UTF8_SUBSTITUTE,
			512) == SUCCESS && encoded.s != NULL) {
		FILE *fp = fopen(cfg.output_path, "wb");
		if (fp != NULL) {
			fwrite(ZSTR_VAL(encoded.s), 1, ZSTR_LEN(encoded.s), fp);
			fclose(fp);
		}
	}

	smart_str_free(&encoded);
	zval_ptr_dtor(&root);
	return count;
}

static void sqlq_write_debug(uint32_t matched)
{
	FILE *fp;
	zval *zv;
	uint32_t i = 0;

	if (!cfg.active || cfg.output_path == NULL) {
		return;
	}
	fp = fopen("/tmp/sql/sqlquery_debug.log", "wb");
	if (fp == NULL) {
		return;
	}
	fprintf(fp, "target_file=%s\n", cfg.file != NULL ? cfg.file : "");
	fprintf(fp, "target_line=%ld\n", (long)cfg.line);
	fprintf(fp, "output=%s\n", cfg.output_path);
	fprintf(fp, "matched_queries=%u\n", matched);
	if (matched == 0) {
		fprintf(fp, "result=no matching query executed in this request\n");
	} else {
		ZEND_HASH_MAP_FOREACH_VAL(&sqlq_records, zv) {
			sqlq_ctx *ctx = (sqlq_ctx *)Z_PTR_P(zv);
			if (ctx == NULL || !ctx->selected || !ctx->executed) {
				continue;
			}
			i++;
			fprintf(fp, "[%u] kind=%s rows=%llu", i,
				ctx->is_ps ? "prepared" : "query",
				(unsigned long long)ctx->row_count);
			if (ctx->has_affected_rows) {
				fprintf(fp, " affected_rows=%lld", (long long)ctx->affected_rows);
			}
			fprintf(fp, " sql=%.300s\n", ctx->sql != NULL ? ctx->sql : "");
		} ZEND_HASH_FOREACH_END();
	}
	fclose(fp);
}
/* }}} */

/* {{{ mysqlnd hooks */
static void sqlq_records_add(sqlq_ctx *ctx)
{
	zend_hash_index_update_ptr(&sqlq_records, (zend_ulong)(uintptr_t)ctx, ctx);
}

static enum_func_status sqlq_stmt_prepare(MYSQLND_STMT *const s, const char *const query, const size_t query_len)
{
	enum_func_status ret;
	sqlq_ps_state *state;
	zend_ulong key;

	ret = sqlq_orig_stmt_methods.prepare(s, query, query_len);

	if (!sqlq_request_active || s == NULL || s->data == NULL) {
		return ret;
	}

	key = (zend_ulong)(uintptr_t)s->data;
	if (zend_hash_index_exists(&sqlq_ps_states, key)) {
		zend_hash_index_del(&sqlq_ps_states, key);
	}

	state = ecalloc(1, sizeof(sqlq_ps_state));
	state->sql = estrndup(query, query_len);
	state->sql_len = query_len;
	state->prepared_match = sqlq_frame_matches();
	zend_hash_index_update_ptr(&sqlq_ps_states, key, state);

	return ret;
}

static enum_func_status sqlq_stmt_execute(MYSQLND_STMT *const s)
{
	enum_func_status ret;
	sqlq_ps_state *state = NULL;
	sqlq_ctx *ctx;
	zend_ulong key = 0;
	zend_hrtime_t start;
	bool prepared_match;
	bool selected;
	bool stack_match = false;
	bool origin_match = false;
	const char *sql_text;
	size_t sql_text_len;

	if (sqlq_request_active && s != NULL && s->data != NULL) {
		key = (zend_ulong)(uintptr_t)s->data;
		state = zend_hash_index_find_ptr(&sqlq_ps_states, key);
	}

	start = zend_hrtime();
	ret = sqlq_orig_stmt_methods.execute(s);

	if (!sqlq_request_active || s == NULL || s->data == NULL) {
		return ret;
	}

	if (ret != PASS) {
		if (zend_hash_index_exists(&sqlq_stmt_current, key)) {
			zend_hash_index_del(&sqlq_stmt_current, key);
		}
		return ret;
	}

	prepared_match = state != NULL ? state->prepared_match : false;
	sql_text = state != NULL ? state->sql : "";
	sql_text_len = state != NULL ? state->sql_len : 0;
	selected = sqlq_query_selected(sql_text, sql_text_len, prepared_match,
		&stack_match, &origin_match);

	ctx = sqlq_ctx_new(sql_text, sql_text_len);
	ctx->is_ps = true;
	ctx->prepared_match = prepared_match;
	ctx->selected = selected;
	ctx->query_stack_match = stack_match;
	ctx->matched_at_origin = origin_match;
	ctx->executed = true;
	ctx->execute_ms = sqlq_ns_to_ms(zend_hrtime() - start);

	ctx->affected_rows = s->m->get_affected_rows(s);
	ctx->has_affected_rows = (ctx->affected_rows != (uint64_t)-1);
	ctx->last_insert_id = s->m->get_last_insert_id(s);
	sqlq_capture_params(ctx, s);
	sqlq_parse_write(ctx);

	sqlq_records_add(ctx);
	zend_hash_index_update_ptr(&sqlq_stmt_current, key, ctx);

	if (s->data->result != NULL) {
		sqlq_capture_fields(ctx, s->data->result);
	}

	return ret;
}

static enum_func_status sqlq_conn_query(MYSQLND_CONN_DATA *conn, const char *const query, const size_t query_len)
{
	enum_func_status ret;
	bool matched_by_frame;
	bool matched_by_prepare;
	bool selected;
	bool stack_match = false;
	bool origin_match = false;
	zend_hrtime_t start;
	sqlq_ctx *ctx;
	zend_ulong key;

	if (!sqlq_request_active || conn == NULL) {
		return sqlq_orig_conn_methods.query(conn, query, query_len);
	}

	key = (zend_ulong)(uintptr_t)conn;
	matched_by_frame = sqlq_frame_matches();
	matched_by_prepare = !matched_by_frame && sqlq_prepare_site_matches();
	selected = sqlq_query_selected(query, query_len, matched_by_prepare,
		&stack_match, &origin_match);

	start = zend_hrtime();
	ret = sqlq_orig_conn_methods.query(conn, query, query_len);
	if (ret != PASS) {
		if (zend_hash_index_exists(&sqlq_conn_current, key)) {
			zend_hash_index_del(&sqlq_conn_current, key);
		}
		return ret;
	}

	ctx = sqlq_ctx_new(query, query_len);
	ctx->is_ps = false;
	ctx->prepared_match = matched_by_prepare;
	ctx->selected = selected;
	ctx->query_stack_match = stack_match;
	ctx->matched_at_origin = origin_match;
	ctx->executed = true;
	ctx->execute_ms = sqlq_ns_to_ms(zend_hrtime() - start);

	ctx->affected_rows = conn->m->get_affected_rows(conn);
	ctx->has_affected_rows = (ctx->affected_rows != (uint64_t)-1);
	ctx->last_insert_id = conn->m->get_last_insert_id(conn);
	sqlq_parse_write(ctx);

	sqlq_records_add(ctx);
	zend_hash_index_update_ptr(&sqlq_conn_current, key, ctx);

	return ret;
}

static enum_func_status sqlq_res_fetch_row(MYSQLND_RES *result, zval **row_ptr,
		const unsigned int flags, bool *fetched_anything)
{
	enum_func_status ret;
	sqlq_ctx *ctx = NULL;
	zend_hrtime_t start = 0;
	bool timed = false;

	if (sqlq_request_active && result != NULL) {
		MYSQLND_STMT_DATA *stmt_data = NULL;

		if (result->stored_data != NULL) {
			stmt_data = result->stored_data->stmt;
		} else if (result->unbuf != NULL) {
			stmt_data = result->unbuf->stmt;
		}

		if (stmt_data != NULL) {
			ctx = zend_hash_index_find_ptr(&sqlq_stmt_current, (zend_ulong)(uintptr_t)stmt_data);
		} else if (result->conn != NULL) {
			ctx = zend_hash_index_find_ptr(&sqlq_conn_current, (zend_ulong)(uintptr_t)result->conn);
		}
		if (ctx != NULL && !ctx->executed) {
			ctx = NULL;
		}
		if (ctx != NULL) {
			if (!ctx->selected && !ctx->query_stack_match && sqlq_frame_matches()) {
				ctx->selected = true;
				ctx->matched_at_fetch = true;
			}
			if (ctx->selected) {
				start = zend_hrtime();
				timed = true;
			} else {
				ctx = NULL;
			}
		}
	}

	ret = sqlq_orig_res_methods.fetch_row(result, row_ptr, flags, fetched_anything);

	if (ctx != NULL) {
		if (timed) {
			ctx->fetch_ms += sqlq_ns_to_ms(zend_hrtime() - start);
		}
		if (ret == PASS && fetched_anything != NULL && *fetched_anything &&
				row_ptr != NULL && *row_ptr != NULL) {
			sqlq_capture_fields(ctx, result);
			sqlq_capture_current_row(ctx, result);
		}
	}
	return ret;
}
/* }}} */

/* {{{ PDO prepare-site tracking */
static void sqlq_site_dtor(zval *zv)
{
	sqlq_site *site = (sqlq_site *)Z_PTR_P(zv);
	if (site != NULL) {
		if (site->file != NULL) {
			efree(site->file);
		}
		efree(site);
	}
}

static void sqlq_record_prepare_site(zval *object)
{
	const char *file = NULL;
	uint32_t line = 0;
	sqlq_site *site;

	if (object == NULL || Z_TYPE_P(object) != IS_OBJECT) {
		return;
	}
	if (!sqlq_get_user_frame(&file, &line)) {
		return;
	}
	site = emalloc(sizeof(sqlq_site));
	site->file = estrdup(file);
	site->line = (zend_long)line;
	zend_hash_index_update_ptr(&sqlq_prepare_sites, Z_OBJ_HANDLE_P(object), site);
}

static void sqlq_call_original_internal(zend_execute_data *execute_data, zval *return_value)
{
	if (sqlq_orig_execute_internal != NULL) {
		sqlq_orig_execute_internal(execute_data, return_value);
	} else {
		execute_internal(execute_data, return_value);
	}
}

static void sqlq_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
	zend_function *func;

	if (!sqlq_request_active || execute_data == NULL || execute_data->func == NULL) {
		sqlq_call_original_internal(execute_data, return_value);
		return;
	}

	func = execute_data->func;
	if (func->type != ZEND_INTERNAL_FUNCTION || func->common.scope == NULL ||
			func->common.function_name == NULL) {
		sqlq_call_original_internal(execute_data, return_value);
		return;
	}

	if (zend_string_equals_literal(func->common.scope->name, "PDO") &&
			zend_string_equals_literal(func->common.function_name, "prepare")) {
		zval *rv;
		sqlq_call_original_internal(execute_data, return_value);
		rv = return_value != NULL ? return_value : execute_data->return_value;
		if (rv != NULL && Z_TYPE_P(rv) == IS_OBJECT) {
			sqlq_record_prepare_site(rv);
		}
		return;
	}

	if (zend_string_equals_literal(func->common.scope->name, "PDOStatement") &&
			zend_string_equals_literal(func->common.function_name, "execute")) {
		sqlq_site *site = NULL;
		bool old_in_execute = sqlq_in_pdo_execute;
		char *old_file = sqlq_pdo_execute_file;
		zend_long old_line = sqlq_pdo_execute_line;

		if (Z_TYPE(execute_data->This) == IS_OBJECT) {
			site = zend_hash_index_find_ptr(&sqlq_prepare_sites,
				Z_OBJ_HANDLE(execute_data->This));
		}
		sqlq_in_pdo_execute = true;
		sqlq_pdo_execute_file = site != NULL ? site->file : NULL;
		sqlq_pdo_execute_line = site != NULL ? site->line : 0;

		sqlq_call_original_internal(execute_data, return_value);

		sqlq_in_pdo_execute = old_in_execute;
		sqlq_pdo_execute_file = old_file;
		sqlq_pdo_execute_line = old_line;
		return;
	}

	sqlq_call_original_internal(execute_data, return_value);
}
/* }}} */

/* {{{ module lifecycle */
static PHP_MINIT_FUNCTION(sqlquery)
{
	MYSQLND_CLASS_METHODS_TYPE(mysqlnd_stmt) *stmt_methods;
	MYSQLND_CLASS_METHODS_TYPE(mysqlnd_conn_data) *conn_methods;
	MYSQLND_CLASS_METHODS_TYPE(mysqlnd_res) *res_methods;

	if (!zend_hash_str_exists(&module_registry, "mysqlnd", sizeof("mysqlnd") - 1)) {
		return SUCCESS;
	}

	stmt_methods = mysqlnd_stmt_get_methods();
	if (stmt_methods != NULL) {
		memcpy(&sqlq_orig_stmt_methods, stmt_methods, sizeof(sqlq_orig_stmt_methods));
		memcpy(&sqlq_our_stmt_methods, stmt_methods, sizeof(sqlq_our_stmt_methods));
		sqlq_our_stmt_methods.prepare = sqlq_stmt_prepare;
		sqlq_our_stmt_methods.execute = sqlq_stmt_execute;
		mysqlnd_stmt_set_methods(&sqlq_our_stmt_methods);
	}

	conn_methods = mysqlnd_conn_data_get_methods();
	if (conn_methods != NULL) {
		memcpy(&sqlq_orig_conn_methods, conn_methods, sizeof(sqlq_orig_conn_methods));
		memcpy(&sqlq_our_conn_methods, conn_methods, sizeof(sqlq_our_conn_methods));
		sqlq_our_conn_methods.query = sqlq_conn_query;
		mysqlnd_conn_data_set_methods(&sqlq_our_conn_methods);
	}

	res_methods = mysqlnd_result_get_methods();
	if (res_methods != NULL) {
		memcpy(&sqlq_orig_res_methods, res_methods, sizeof(sqlq_orig_res_methods));
		memcpy(&sqlq_our_res_methods, res_methods, sizeof(sqlq_our_res_methods));
		sqlq_our_res_methods.fetch_row = sqlq_res_fetch_row;
		mysqlnd_result_set_methods(&sqlq_our_res_methods);
	}

	sqlq_orig_execute_internal = zend_execute_internal;
	zend_execute_internal = sqlq_execute_internal;

	sqlq_hooked = true;
	return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(sqlquery)
{
	(void)type;
	(void)module_number;

	if (sqlq_hooked) {
		if (mysqlnd_stmt_get_methods() == &sqlq_our_stmt_methods) {
			mysqlnd_stmt_set_methods(&sqlq_orig_stmt_methods);
		}
		if (mysqlnd_conn_data_get_methods() == &sqlq_our_conn_methods) {
			mysqlnd_conn_data_set_methods(&sqlq_orig_conn_methods);
		}
		mysqlnd_result_set_methods(&sqlq_orig_res_methods);
		if (zend_execute_internal == sqlq_execute_internal) {
			zend_execute_internal = sqlq_orig_execute_internal;
		}
		sqlq_hooked = false;
	}
	return SUCCESS;
}

static PHP_RINIT_FUNCTION(sqlquery)
{
	(void)type;
	(void)module_number;

	sqlq_request_active = false;
	if (!sqlq_hooked) {
		return SUCCESS;
	}
	if (!sqlq_load_config()) {
		return SUCCESS;
	}

	zend_hash_init(&sqlq_ps_states, 8, NULL, sqlq_ps_state_dtor, 0);
	zend_hash_init(&sqlq_stmt_current, 8, NULL, NULL, 0);
	zend_hash_init(&sqlq_conn_current, 4, NULL, NULL, 0);
	zend_hash_init(&sqlq_records, 8, NULL, sqlq_ctx_dtor, 0);
	zend_hash_init(&sqlq_prepare_sites, 8, NULL, sqlq_site_dtor, 0);
	sqlq_request_active = true;
	return SUCCESS;
}

static PHP_RSHUTDOWN_FUNCTION(sqlquery)
{
	(void)type;
	(void)module_number;

	if (sqlq_request_active) {
		uint32_t matched = sqlq_flush_output();
		sqlq_write_debug(matched);
		zend_hash_destroy(&sqlq_stmt_current);
		zend_hash_destroy(&sqlq_conn_current);
		zend_hash_destroy(&sqlq_ps_states);
		zend_hash_destroy(&sqlq_records);
		zend_hash_destroy(&sqlq_prepare_sites);
		sqlq_request_active = false;
	}
	sqlq_reset_config();
	return SUCCESS;
}

static PHP_MINFO_FUNCTION(sqlquery)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "sqlquery support", "enabled");
	php_info_print_table_row(2, "Version", PHP_SQLQUERY_VERSION);
	php_info_print_table_row(2, "mysqlnd hooks", sqlq_hooked ? "installed" : "inactive");
	php_info_print_table_row(2, "config file", SQLQ_CONFIG_PATH);
	php_info_print_table_end();
}
/* }}} */

zend_module_entry sqlquery_module_entry = {
	STANDARD_MODULE_HEADER,
	"sqlquery",
	NULL,
	PHP_MINIT(sqlquery),
	PHP_MSHUTDOWN(sqlquery),
	PHP_RINIT(sqlquery),
	PHP_RSHUTDOWN(sqlquery),
	PHP_MINFO(sqlquery),
	PHP_SQLQUERY_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SQLQUERY
ZEND_GET_MODULE(sqlquery)
#endif
