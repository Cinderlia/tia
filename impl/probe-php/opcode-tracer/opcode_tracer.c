/*
 * Directed opcode tracer for PHP 8.4.
 *
 * The tracer is armed by writing a small flat JSON config to a fixed path
 * (default /tmp/trace_query.json, override with TRACE_QUERY_CONFIG).  The
 * config is read once per request in RINIT and the trace is written to
 * <TRACE_OUTPUT_DIR>/<output>.  The file is truncated at request start and
 * closed at request shutdown, so multiple workers never share a trace file.
 *
 * Directed filters:
 *   file       exact path (realpath compare) or a path suffix
 *   line_from  first source line to keep (0 = no lower bound)
 *   line_to    last source line to keep (0 = no upper bound)
 *   function   keep only opcodes whose enclosing function name contains this
 *   max_depth  keep only frames with at most this many parent frames (0 = any)
 *   max_lines  hard cap on emitted lines (0 = 200000)
 *   exclude    comma separated opcode names to drop
 *   output     trace file name (letters, digits, dot, dash, underscore)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_opcode_tracer.h"
#include "zend_execute.h"
#include "zend_vm.h"
#include "zend_vm_opcodes.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef ZEND_VM_LAST_OPCODE
#define ZEND_VM_LAST_OPCODE 255
#endif

#define TRACE_DEFAULT_CONFIG "/tmp/trace_query.json"
#define TRACE_DEFAULT_DIR "/tmp/trace"
#define TRACE_DEFAULT_MAX_LINES 200000
#define TRACE_DEFAULT_EXCLUDE "NOP,EXT_STMT,EXT_FCALL_BEGIN,EXT_FCALL_END,EXT_NOP,TICKS"
#define TRACE_MAX_STRING 4096
#define TRACE_MAX_TARGETS 16

typedef struct {
    char file[PATH_MAX];
    char function[256];
    long line_from;
    long line_to;
} trace_target;

typedef struct {
    char function[256];
    char exclude[512];
    char output[256];
    long max_depth;
    long max_lines;
    trace_target targets[TRACE_MAX_TARGETS];
    int target_count;
} trace_config;

static FILE *trace_fp = NULL;
static trace_config trace_cfg;
static long trace_lines = 0;
static zend_bool trace_truncated = 0;

static void trace_config_reset(trace_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_lines = TRACE_DEFAULT_MAX_LINES;
    snprintf(cfg->exclude, sizeof(cfg->exclude), "%s", TRACE_DEFAULT_EXCLUDE);
}

/* --- flat JSON helpers ------------------------------------------------- */

static const char *json_find_key(const char *json, const char *key)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) {
        return NULL;
    }
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        p++;
    }
    if (*p != ':') {
        return NULL;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        p++;
    }
    return p;
}

static int json_get_string(const char *json, const char *key, char *out, size_t out_size)
{
    const char *p = json_find_key(json, key);
    if (!p || *p != '"' || out_size == 0) {
        return 0;
    }
    p++;
    size_t pos = 0;
    while (*p && *p != '"' && pos + 1 < out_size) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': out[pos++] = '\n'; break;
                case 't': out[pos++] = '\t'; break;
                case 'r': out[pos++] = '\r'; break;
                default: out[pos++] = *p; break;
            }
            p++;
            continue;
        }
        out[pos++] = *p++;
    }
    out[pos] = '\0';
    return 1;
}

static long json_get_long(const char *json, const char *key, long fallback)
{
    const char *p = json_find_key(json, key);
    if (!p) {
        return fallback;
    }
    char *end = NULL;
    long value = strtol(p, &end, 10);
    return end == p ? fallback : value;
}

static int valid_output_name(const char *name)
{
    if (!*name || strlen(name) >= 200) {
        return 0;
    }
    if (strstr(name, "..") != NULL || strchr(name, '/') != NULL) {
        return 0;
    }
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) {
            return 0;
        }
    }
    return 1;
}

static void trace_config_load(trace_config *cfg)
{
    char path[PATH_MAX];
    const char *env_path = getenv("TRACE_QUERY_CONFIG");
    snprintf(path, sizeof(path), "%s", (env_path && *env_path) ? env_path : TRACE_DEFAULT_CONFIG);

    char buf[TRACE_MAX_STRING];
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return;
    }
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    /* A list of targets wins; otherwise fall back to a single file/range. */
    const char *arr = json_find_key(buf, "targets");
    if (arr && *arr == '[') {
        const char *p = arr + 1;
        while (cfg->target_count < TRACE_MAX_TARGETS) {
            const char *open = strchr(p, '{');
            if (!open) {
                break;
            }
            const char *close = strchr(open, '}');
            if (!close) {
                break;
            }
            size_t item_len = (size_t)(close - open + 1);
            if (item_len >= TRACE_MAX_STRING) {
                item_len = TRACE_MAX_STRING - 1;
            }
            char item[TRACE_MAX_STRING];
            memcpy(item, open, item_len);
            item[item_len] = '\0';
            trace_target *t = &cfg->targets[cfg->target_count];
            if (json_get_string(item, "file", t->file, sizeof(t->file)) && t->file[0]) {
                json_get_string(item, "function", t->function, sizeof(t->function));
                t->line_from = json_get_long(item, "line_from", 0);
                t->line_to = json_get_long(item, "line_to", 0);
                if (t->line_from == 0 && t->line_to == 0) {
                    long one = json_get_long(item, "line", 0);
                    if (one > 0) {
                        t->line_from = one;
                        t->line_to = one;
                    }
                }
                cfg->target_count++;
            }
            p = close + 1;
        }
    }
    if (cfg->target_count == 0) {
        trace_target *t = &cfg->targets[0];
        if (json_get_string(buf, "file", t->file, sizeof(t->file)) && t->file[0]) {
            json_get_string(buf, "function", t->function, sizeof(t->function));
            t->line_from = json_get_long(buf, "line_from", 0);
            t->line_to = json_get_long(buf, "line_to", 0);
            cfg->target_count = 1;
        }
    }
    json_get_string(buf, "exclude", cfg->exclude, sizeof(cfg->exclude));
    if (!cfg->exclude[0]) {
        snprintf(cfg->exclude, sizeof(cfg->exclude), "%s", TRACE_DEFAULT_EXCLUDE);
    }
    json_get_string(buf, "output", cfg->output, sizeof(cfg->output));
    cfg->max_depth = json_get_long(buf, "max_depth", 0);
    cfg->max_lines = json_get_long(buf, "max_lines", TRACE_DEFAULT_MAX_LINES);
    if (cfg->max_lines <= 0) {
        cfg->max_lines = TRACE_DEFAULT_MAX_LINES;
    }
}

static int trace_opcode_excluded(const char *opname)
{
    const char *p = trace_cfg.exclude;
    while (p && *p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len > 0 && strlen(opname) == len && strncmp(p, opname, len) == 0) {
            return 1;
        }
        if (!comma) {
            break;
        }
        p = comma + 1;
    }
    return 0;
}

static int trace_file_matches(const char *path, const char *want)
{
    if (!want[0]) {
        return 1;
    }
    if (want[0] == '/') {
        return strcmp(path, want) == 0;
    }
    size_t path_len = strlen(path);
    size_t want_len = strlen(want);
    return path_len >= want_len && strcmp(path + path_len - want_len, want) == 0;
}

/* Return the index of the first configured target matching this opcode. */
static int trace_target_index(const char *path, long line, const char *funcname)
{
    int i;
    for (i = 0; i < trace_cfg.target_count; i++) {
        const trace_target *t = &trace_cfg.targets[i];
        if (!trace_file_matches(path, t->file)) {
            continue;
        }
        if (t->line_from > 0 && line < t->line_from) {
            continue;
        }
        if (t->line_to > 0 && line > t->line_to) {
            continue;
        }
        if (t->function[0]) {
            if (!funcname || strstr(funcname, t->function) == NULL) {
                continue;
            }
        }
        return i;
    }
    return -1;
}

static int trace_frame_depth(zend_execute_data *execute_data)
{
    int depth = 0;
    zend_execute_data *frame = execute_data->prev_execute_data;
    while (frame && depth < 1000) {
        if (frame->func && ZEND_USER_CODE(frame->func->type)) {
            depth++;
        }
        frame = frame->prev_execute_data;
    }
    return depth;
}

static zend_always_inline bool opcode_tracer_is_jump_opcode(zend_uchar opcode)
{
    return opcode == ZEND_JMP || opcode == ZEND_JMPZ || opcode == ZEND_JMPNZ;
}

static zend_always_inline long opcode_tracer_get_jump_target(
    const zend_op *base_opcodes,
    const zend_op *opline,
    long opidx
)
{
#if ZEND_USE_ABS_JMP_ADDR
    if (base_opcodes && opline->op2.jmp_addr) {
        return (long)(opline->op2.jmp_addr - base_opcodes);
    }
    return -1;
#else
    (void) base_opcodes;
    return opidx + (long) opline->op2.jmp_offset + 1;
#endif
}

static int opcode_tracer_handler(zend_execute_data *execute_data)
{
    if (!trace_fp || trace_truncated || !execute_data || !execute_data->opline) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    const zend_op *opline = execute_data->opline;
    const zend_op_array *op_array = NULL;
    const char *filename = NULL;
    if (execute_data->func && ZEND_USER_CODE(execute_data->func->type)) {
        op_array = &execute_data->func->op_array;
        filename = ZSTR_VAL(op_array->filename);
    }
    if (!filename || !execute_data->func) {
        return ZEND_USER_OPCODE_DISPATCH;
    }

    char resolved[PATH_MAX];
    const char *path_out = filename;
    if (realpath(filename, resolved)) {
        path_out = resolved;
    }
    long line = (long) opline->lineno;
    const char *funcname = NULL;
    if (execute_data->func->common.function_name) {
        funcname = ZSTR_VAL(execute_data->func->common.function_name);
    }
    int target_index = trace_target_index(path_out, line, funcname);
    if (target_index < 0) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    int depth = trace_frame_depth(execute_data);
    if (trace_cfg.max_depth > 0 && depth > trace_cfg.max_depth) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    const char *opname = zend_get_opcode_name(opline->opcode);
    if (!opname) {
        opname = "UNKNOWN";
    }
    if (trace_opcode_excluded(opname)) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    if (trace_lines >= trace_cfg.max_lines) {
        fprintf(trace_fp, "#truncated max_lines=%ld\n", trace_cfg.max_lines);
        trace_truncated = 1;
        return ZEND_USER_OPCODE_DISPATCH;
    }

    long opidx = -1;
    if (op_array && op_array->opcodes) {
        opidx = (long)(opline - op_array->opcodes);
    }
    char o1[128] = {0}, o2[128] = {0}, res[64] = {0};
    if (opline->op1_type == IS_CV) {
        int cv = opline->op1.var;
        if (op_array && op_array->vars && cv >= 0 && cv < (int) op_array->last_var) {
            snprintf(o1, sizeof(o1), "CV:%s", ZSTR_VAL(op_array->vars[cv]));
        } else {
            snprintf(o1, sizeof(o1), "CV:%d", cv);
        }
    } else if (opline->op1_type == IS_CONST) {
        snprintf(o1, sizeof(o1), "CONST:%u", (unsigned) opline->op1.constant);
    } else if (opline->op1_type == IS_TMP_VAR) {
        snprintf(o1, sizeof(o1), "TMP");
    } else if (opline->op1_type == IS_VAR) {
        snprintf(o1, sizeof(o1), "VAR");
    }
    if (opline->op2_type == IS_CV) {
        int cv = opline->op2.var;
        if (op_array && op_array->vars && cv >= 0 && cv < (int) op_array->last_var) {
            snprintf(o2, sizeof(o2), "CV:%s", ZSTR_VAL(op_array->vars[cv]));
        } else {
            snprintf(o2, sizeof(o2), "CV:%d", cv);
        }
    } else if (opline->op2_type == IS_CONST) {
        snprintf(o2, sizeof(o2), "CONST:%u", (unsigned) opline->op2.constant);
    } else if (opline->op2_type == IS_TMP_VAR) {
        snprintf(o2, sizeof(o2), "TMP");
    } else if (opline->op2_type == IS_VAR) {
        snprintf(o2, sizeof(o2), "VAR");
    }
    if (opline->result_type == IS_TMP_VAR) {
        snprintf(res, sizeof(res), "TMP");
    } else if (opline->result_type == IS_VAR) {
        snprintf(res, sizeof(res), "VAR");
    } else if (opline->result_type == IS_CV) {
        snprintf(res, sizeof(res), "CV");
    }

    char branch_buf[128];
    branch_buf[0] = '\0';
    long target_idx = -1;
    if (opcode_tracer_is_jump_opcode(opline->opcode)) {
#if ZEND_USE_ABS_JMP_ADDR
        target_idx = opcode_tracer_get_jump_target(op_array->opcodes, opline, opidx);
        if (target_idx >= 0) {
            snprintf(branch_buf, sizeof(branch_buf), "branch=%s:%ld", opname, target_idx);
        }
#else
        snprintf(branch_buf, sizeof(branch_buf), "branch=%s:%ld", opname, (long) opline->op2.jmp_offset);
        target_idx = opcode_tracer_get_jump_target(op_array->opcodes, opline, opidx);
#endif
    }

    fprintf(trace_fp, "%s:%ld | op=%s | pc=%ld | depth=%d | target=%d",
            path_out, line, opname, opidx, depth, target_index);
    if (funcname) {
        fprintf(trace_fp, " | func=%s", funcname);
    }
    if (o1[0]) fprintf(trace_fp, " | o1=%s", o1);
    if (o2[0]) fprintf(trace_fp, " | o2=%s", o2);
    if (res[0]) fprintf(trace_fp, " | res=%s", res);
    if (branch_buf[0]) fprintf(trace_fp, " | %s", branch_buf);
    if (target_idx >= 0) fprintf(trace_fp, " | bpc=%ld", target_idx);
    fprintf(trace_fp, "\n");
    trace_lines++;
    return ZEND_USER_OPCODE_DISPATCH;
}

PHP_MINIT_FUNCTION(opcode_tracer)
{
    const char *dir = getenv("TRACE_OUTPUT_DIR");
    if (!dir || !*dir) {
        dir = TRACE_DEFAULT_DIR;
    }
    mkdir(dir, 0777);

    zend_uchar i;
    for (i = 0; i <= ZEND_VM_LAST_OPCODE; i++) {
        zend_set_user_opcode_handler(i, opcode_tracer_handler);
    }
    return SUCCESS;
}

PHP_RINIT_FUNCTION(opcode_tracer)
{
#if defined(ZTS) && defined(COMPILE_DL_OPCODE_TRACER)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    trace_fp = NULL;
    trace_lines = 0;
    trace_truncated = 0;
    trace_config_reset(&trace_cfg);
    trace_config_load(&trace_cfg);
    if (!trace_cfg.output[0] || !valid_output_name(trace_cfg.output)) {
        return SUCCESS;
    }
    const char *dir = getenv("TRACE_OUTPUT_DIR");
    if (!dir || !*dir) {
        dir = TRACE_DEFAULT_DIR;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, trace_cfg.output);
    trace_fp = fopen(path, "w");
    if (trace_fp) {
        setbuf(trace_fp, NULL);
    }
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(opcode_tracer)
{
    if (trace_fp) {
        fclose(trace_fp);
        trace_fp = NULL;
    }
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(opcode_tracer)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(opcode_tracer)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "opcode_tracer support", "enabled");
    php_info_print_table_row(2, "Version", PHP_OPCODE_TRACER_VERSION);
    php_info_print_table_row(2, "Config", TRACE_DEFAULT_CONFIG);
    php_info_print_table_row(2, "Output", TRACE_DEFAULT_DIR);
    php_info_print_table_end();
}

const zend_function_entry opcode_tracer_functions[] = {
    PHP_FE_END
};

zend_module_entry opcode_tracer_module_entry = {
    STANDARD_MODULE_HEADER,
    "opcode_tracer",
    opcode_tracer_functions,
    PHP_MINIT(opcode_tracer),
    PHP_MSHUTDOWN(opcode_tracer),
    PHP_RINIT(opcode_tracer),
    PHP_RSHUTDOWN(opcode_tracer),
    PHP_MINFO(opcode_tracer),
    PHP_OPCODE_TRACER_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_OPCODE_TRACER
ZEND_GET_MODULE(opcode_tracer)
#endif
