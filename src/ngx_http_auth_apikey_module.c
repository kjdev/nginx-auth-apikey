/* Module entry point: registers the module with NGINX. Directives are
 * parsed and merged here; preconfiguration exposes the $apikey_* variables,
 * postconfiguration registers the authentication phase handler. */

#include <nxe_phase.h>

#include "ngx_http_auth_apikey_module.h"
#include "ngx_http_auth_apikey_handler.h"

static char *ngx_http_auth_apikey_conf_set_key_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_apikey_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_apikey_conf_set_require_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static void *ngx_http_auth_apikey_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_apikey_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_auth_apikey_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_apikey_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_apikey_init(ngx_conf_t *cf);

/* Fixed set (ADR-0007): no prefix variables, no dynamic aliases. Indices
 * match the HMGET field order in ngx_http_auth_apikey_handler.h. */
static ngx_http_variable_t ngx_http_auth_apikey_vars[] = {

    { ngx_string("apikey_user_id"), NULL, ngx_http_auth_apikey_variable,
      NGX_HTTP_AUTH_APIKEY_FIELD_USER_ID, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("apikey_scope"), NULL, ngx_http_auth_apikey_variable,
      NGX_HTTP_AUTH_APIKEY_FIELD_SCOPE, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("apikey_quota"), NULL, ngx_http_auth_apikey_variable,
      NGX_HTTP_AUTH_APIKEY_FIELD_QUOTA, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("apikey_enabled"), NULL, ngx_http_auth_apikey_variable,
      NGX_HTTP_AUTH_APIKEY_FIELD_ENABLED, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};

static ngx_command_t ngx_http_auth_apikey_commands[] = {

    { ngx_string("auth_apikey"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF | NGX_CONF_TAKE12,
      ngx_http_auth_apikey_conf_set_key_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_apikey_pass"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_http_auth_apikey_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_apikey_require"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF | NGX_CONF_1MORE,
      ngx_http_auth_apikey_conf_set_require_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_apikey_module_ctx = {
    ngx_http_auth_apikey_add_variables, /* preconfiguration */
    ngx_http_auth_apikey_init,   /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_auth_apikey_create_loc_conf, /* create location configuration */
    ngx_http_auth_apikey_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_apikey_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_apikey_module_ctx, /* module context */
    ngx_http_auth_apikey_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};

/* "auth_apikey <realm> [key=$variable] | off;" */
static char *
ngx_http_auth_apikey_conf_set_key_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_apikey_loc_conf_t *lcf;
    ngx_str_t *value;
    static const char prefix[] = "key=";
    static const size_t prefix_len = sizeof(prefix) - 1;

    lcf = conf;
    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lcf->enabled = 0;
        return NGX_CONF_OK;
    }

    lcf->enabled = 1;
    lcf->realm = value[1];

    if (cf->args->nelts > 2) {
        if (value[2].len <= prefix_len
            || ngx_strncmp(value[2].data, prefix, prefix_len) != 0)
        {
            return "invalid parameter, expected \"key=$variable\"";
        }

        value[2].data += prefix_len;
        value[2].len -= prefix_len;

        if (value[2].len == 0 || value[2].data[0] != '$') {
            return "key is not a variable specified";
        }

        value[2].data++;
        value[2].len--;

        lcf->key_variable = ngx_http_get_variable_index(cf, &value[2]);
        if (lcf->key_variable == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/* "auth_apikey_pass <upstream> | <host:port> | $variable;" */
static char *
ngx_http_auth_apikey_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_apikey_loc_conf_t *lcf;
    ngx_str_t *value;
    ngx_uint_t n;
    ngx_url_t url;
    ngx_http_compile_complex_value_t ccv;

    lcf = conf;

    if (lcf->upstream.upstream || lcf->complex_target) {
        return "is duplicate";
    }

    value = cf->args->elts;

    n = ngx_http_script_variables_count(&value[1]);
    if (n) {
        lcf->complex_target =
            ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (lcf->complex_target == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = lcf->complex_target;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = value[1];
    url.no_resolve = 1;

    lcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0);
    if (lcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* "auth_apikey_require $variable ... [error=code];" */
static char *
ngx_http_auth_apikey_conf_set_require_variable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_apikey_loc_conf_t *lcf;
    ngx_str_t *value;
    ngx_uint_t i, n;
    ngx_int_t error_code;
    static const char error_with[] = "error=";
    static const size_t error_with_len = sizeof(error_with) - 1;

    lcf = conf;
    value = cf->args->elts;
    n = cf->args->nelts - 1;
    error_code = NGX_HTTP_UNAUTHORIZED;

    if (lcf->requires == NULL) {
        lcf->requires = ngx_array_create(cf->pool, 4,
                                         sizeof(
                                             ngx_http_auth_apikey_require_variable_t));
        if (lcf->requires == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (value[n].len >= error_with_len
        && ngx_strncmp(value[n].data, error_with, error_with_len) == 0)
    {
        value[n].data += error_with_len;
        value[n].len -= error_with_len;

        error_code = ngx_atoi(value[n].data, value[n].len);
        if (error_code < 400
            || error_code > 599
            || error_code == 444
            || error_code == 499)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" directive error code must be 400-599 "
                               "(excluding 444 and 499): \"%V\"",
                               &cmd->name, &value[n]);
            return NGX_CONF_ERROR;
        }

        --n;
        if (n == 0) {
            return "at least one variable must be specified";
        }
    }

    for (i = 1; i <= n; i++) {
        ngx_http_auth_apikey_require_variable_t *var;
        ngx_http_compile_complex_value_t ccv;

        if (value[i].data[0] != '$') {
            return "not a variable specified";
        }

        var = ngx_array_push(lcf->requires);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(var, sizeof(ngx_http_auth_apikey_require_variable_t));
        var->error = error_code;

        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = &var->value;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_auth_apikey_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_apikey_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_apikey_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->key_variable = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* Hardcoded values: this upstream carries a hand-rolled RESP request
     * and reply, never a client-facing HTTP response. */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 1;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    return conf;
}

static char *
ngx_http_auth_apikey_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_apikey_loc_conf_t *prev = parent;
    ngx_http_auth_apikey_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_str_value(conf->realm, prev->realm, "");
    ngx_conf_merge_value(conf->key_variable, prev->key_variable,
                         NGX_CONF_UNSET);

    if (conf->requires == NULL || conf->requires->nelts == 0) {
        conf->requires = prev->requires;
    } else if (prev->requires && prev->requires->nelts) {
        ngx_uint_t i, len, n;
        ngx_http_auth_apikey_require_variable_t *value, *var;

        len = conf->requires->nelts;
        n = prev->requires->nelts;

        if (ngx_array_push_n(conf->requires, n) == NULL) {
            return NGX_CONF_ERROR;
        }

        value = conf->requires->elts;
        var = prev->requires->elts;

        /* value[n..n+len) overlaps value[0..len) whenever len > n, so the
         * child entries must be copied back-to-front: a forward copy would
         * overwrite not-yet-read source slots before they are moved. */
        for (i = len; i > 0; i--) {
            value[n + i - 1] = value[i - 1];
        }
        for (i = 0; i < n; i++) {
            value[i] = var[i];
        }
    }

    if (conf->complex_target == NULL) {
        conf->complex_target = prev->complex_target;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->enabled
        && conf->upstream.upstream == NULL
        && conf->complex_target == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"auth_apikey\" requires \"auth_apikey_pass\"");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);
    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_apikey_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_auth_apikey_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

/* Reference: ngx_http_auth_jwt claim exposure guard. ctx->verified only
 * becomes true after the enabled check passes (ADR-0006/ADR-0012), so a
 * request that never reached that point, or is mid-flight on an internal
 * redirect, never observes a half-decided reply. */
static ngx_int_t
ngx_http_auth_apikey_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t field;
    ngx_http_auth_apikey_ctx_t *ctx;

    field = (ngx_uint_t) data;

    ctx = ngx_http_auth_apikey_get_module_ctx(r);

    if (ctx == NULL || !ctx->verified || ctx->fields_nil[field]) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->fields[field].data;
    v->len = ctx->fields[field].len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

/* Registers the phase handler alongside auth_basic/auth_request/auth_jwt,
 * so "satisfy" composes with them (ADR-0002/ADR-0012). nxe_phase_add_handler()
 * (NXE_PHASE_PRIO_APIKEY = 300) fixes evaluation order relative to the other
 * ACCESS-phase auth modules (jwt 200 / oauth2-token 250 / webauthn 450 /
 * oidc 500) by priority instead of load_module / --add-module order
 * (ADR-0013). */
static ngx_int_t
ngx_http_auth_apikey_init(ngx_conf_t *cf)
{
    if (nxe_phase_add_handler(cf, NGX_HTTP_ACCESS_PHASE,
                              NXE_PHASE_PRIO_APIKEY,
                              ngx_http_auth_apikey_handler,
                              "auth_apikey") != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
