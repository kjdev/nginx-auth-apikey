#include "ngx_http_auth_apikey_handler.h"
#include "ngx_http_auth_apikey_module.h"
#include "ngx_http_auth_apikey_upstream.h"
#include "ngx_http_auth_apikey_reply.h"
#include "ngx_http_auth_apikey_util.h"
#include "ngx_auth_apikey_hash.h"

static ngx_int_t ngx_http_auth_apikey_extract_key(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf, ngx_str_t *key);
static ngx_int_t ngx_http_auth_apikey_set_www_authenticate(
    ngx_http_request_t *r, ngx_http_auth_apikey_loc_conf_t *alcf);
static ngx_int_t ngx_http_auth_apikey_unauthorized(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf, ngx_flag_t use_default_header);
static void ngx_http_auth_apikey_cleanup(void *data);
static ngx_int_t ngx_http_auth_apikey_start(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf);
static ngx_int_t ngx_http_auth_apikey_process_result(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf, ngx_http_auth_apikey_ctx_t *ctx);

static ngx_int_t ngx_http_auth_apikey_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_apikey_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_apikey_process_header(ngx_http_request_t *r);
static void ngx_http_auth_apikey_abort_request(ngx_http_request_t *r);
static void ngx_http_auth_apikey_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t ngx_http_auth_apikey_filter_init(void *data);
static ngx_int_t ngx_http_auth_apikey_filter(void *data, ssize_t bytes);

/* Reference: ngx_http_auth_jwt_get_module_ctx. Recovers ctx after an
 * internal redirect wipes r->ctx by walking the pool cleanup chain for the
 * sentinel handler address left behind in ngx_http_auth_apikey_start. */
ngx_http_auth_apikey_ctx_t *
ngx_http_auth_apikey_get_module_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t *cln;
    ngx_http_auth_apikey_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_apikey_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {
        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_auth_apikey_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }

    return ctx;
}

/* Sentinel cleanup handler: never does anything itself, its address is used
 * only as a marker to relocate ctx from the pool cleanup chain. */
static void
ngx_http_auth_apikey_cleanup(void *data)
{
    (void) data;
}

ngx_int_t
ngx_http_auth_apikey_handler(ngx_http_request_t *r)
{
    ngx_http_auth_apikey_loc_conf_t *alcf;
    ngx_http_auth_apikey_ctx_t *ctx;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_apikey_module);

    if (!alcf->enabled) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_auth_apikey_get_module_ctx(r);

    if (ctx) {
        return ngx_http_auth_apikey_process_result(r, alcf, ctx);
    }

    return ngx_http_auth_apikey_start(r, alcf);
}

/* Default credential source: "Authorization: ApiKey <key>", scheme matched
 * case-insensitively with one or more separating spaces. With
 * "auth_apikey ... key=$variable", the variable value is taken as the raw
 * key verbatim (no scheme to strip). */
static ngx_int_t
ngx_http_auth_apikey_extract_key(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf, ngx_str_t *key)
{
    static const u_char scheme[] = "ApiKey";
    static const size_t scheme_len = sizeof(scheme) - 1;
    u_char *p, *last;
    ngx_http_variable_value_t *vv;

    if (alcf->key_variable != NGX_CONF_UNSET) {
        vv = ngx_http_get_indexed_variable(r, alcf->key_variable);
        if (vv == NULL || vv->not_found || vv->len == 0) {
            return NGX_DECLINED;
        }

        key->data = vv->data;
        key->len = vv->len;

        return NGX_OK;
    }

    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }

    key->data = r->headers_in.authorization->value.data;
    key->len = r->headers_in.authorization->value.len;

    if (key->len <= scheme_len
        || ngx_strncasecmp(key->data, (u_char *) scheme, scheme_len) != 0)
    {
        return NGX_DECLINED;
    }

    p = key->data + scheme_len;
    last = key->data + key->len;

    if (*p != ' ') {
        return NGX_DECLINED;
    }

    while (p < last && *p == ' ') {
        p++;
    }

    if (p == last) {
        return NGX_DECLINED;
    }

    key->data = p;
    key->len = last - p;

    return NGX_OK;
}

/* Reference: ngx_http_auth_jwt_set_bearer_header. Rolls the list entry back
 * (hash = 0) if the value allocation fails, so a half-built header is never
 * sent. */
static ngx_int_t
ngx_http_auth_apikey_set_www_authenticate(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf)
{
    size_t len;
    u_char *p;
    ngx_table_elt_t *www_authenticate;

    www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (www_authenticate == NULL) {
        return NGX_ERROR;
    }

    www_authenticate->hash = 1;
    www_authenticate->next = NULL;
    ngx_str_set(&www_authenticate->key, "WWW-Authenticate");

    len = sizeof("ApiKey realm=\"\"") - 1 + alcf->realm.len;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        www_authenticate->hash = 0;
        return NGX_ERROR;
    }

    www_authenticate->value.data = p;
    p = ngx_cpymem(p, "ApiKey realm=\"", sizeof("ApiKey realm=\"") - 1);
    p = ngx_cpymem(p, alcf->realm.data, alcf->realm.len);
    *p++ = '"';

    www_authenticate->value.len = p - www_authenticate->value.data;

    return NGX_OK;
}

/* not-found and enabled=="0" must produce the same 401 (no existence
 * oracle, ADR-0008); the header is only attached on the default credential
 * source, matching the challenge a client using that scheme expects. */
static ngx_int_t
ngx_http_auth_apikey_unauthorized(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf, ngx_flag_t use_default_header)
{
    if (use_default_header
        && ngx_http_auth_apikey_set_www_authenticate(r, alcf) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t
ngx_http_auth_apikey_start(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf)
{
    ngx_int_t rc;
    ngx_str_t key;
    u_char hash[NGX_AUTH_APIKEY_SHA256_LEN];
    u_char hex[2 * NGX_AUTH_APIKEY_SHA256_LEN];
    ngx_flag_t use_default_header;
    ngx_http_auth_apikey_ctx_t *ctx;
    ngx_http_upstream_t *u;
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_pool_cleanup_t *cln;

    use_default_header = (alcf->key_variable == NGX_CONF_UNSET);

    rc = ngx_http_auth_apikey_extract_key(r, alcf, &key);

    if (rc != NGX_OK) {
        return ngx_http_auth_apikey_unauthorized(r, alcf, use_default_header);
    }

    if (ngx_auth_apikey_hash_sha256(key.data, key.len, hash) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_hex_dump(hex, hash, NGX_AUTH_APIKEY_SHA256_LEN);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_apikey_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->use_default_header = use_default_header;

    ctx->hash_key.len = sizeof("apikey:cred:") - 1
                        + 2 * NGX_AUTH_APIKEY_SHA256_LEN;
    ctx->hash_key.data = ngx_pnalloc(r->pool, ctx->hash_key.len);
    if (ctx->hash_key.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(ngx_cpymem(ctx->hash_key.data, "apikey:cred:",
                          sizeof("apikey:cred:") - 1),
               hex, 2 * NGX_AUTH_APIKEY_SHA256_LEN);

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_auth_apikey_cleanup;
    cln->data = ctx;

    ngx_http_set_ctx(r, ctx, ngx_http_auth_apikey_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "redis://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_auth_apikey_module;

    u->conf = &alcf->upstream;

    if (alcf->complex_target) {
        ngx_str_t target;
        ngx_url_t url;

        if (ngx_http_complex_value(r, alcf->complex_target, &target)
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memzero(&url, sizeof(ngx_url_t));
        url.url = target;
        url.no_resolve = 1;

        uscf = ngx_http_auth_apikey_upstream_add(r, &url);
        if (uscf == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "auth_apikey: no upstream found: \"%V\"", &target);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        uscf = alcf->upstream.upstream;
    }

    if (uscf->peer.init(r, uscf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->input_filter_init = ngx_http_auth_apikey_filter_init;
    u->input_filter = ngx_http_auth_apikey_filter;
    u->input_filter_ctx = ctx;

    u->create_request = ngx_http_auth_apikey_create_request;
    u->reinit_request = ngx_http_auth_apikey_reinit_request;
    u->process_header = ngx_http_auth_apikey_process_header;
    u->abort_request = ngx_http_auth_apikey_abort_request;
    u->finalize_request = ngx_http_auth_apikey_finalize_request;

    r->main->count++;

    ngx_http_upstream_init(r);

    /* ngx_http_upstream_init installs its own non-buffered read handler;
     * this module drives the RESP read loop itself instead. Reapplied in
     * ngx_http_auth_apikey_reinit_request too, since a reused keepalive
     * connection skips this path. */
    u->read_event_handler = ngx_http_auth_apikey_read_header_handler;

    /* With ignore_client_abort=1, ngx_http_upstream_init_request() never
     * replaces r->write_event_handler with its check_broken_connection
     * variant. But ngx_http_upstream_init() unconditionally re-arms the
     * client connection's write event under edge-triggered epoll, and an
     * idle client socket is essentially always writable. Left as
     * ngx_http_core_run_phases (the pre-existing default from earlier
     * phase processing), that stray writable event fires the phase engine
     * again immediately, before Redis has replied, re-entering this
     * handler with ctx only just pcalloc'd and finalizing a bogus
     * decision early; the real reply then finalizes a second time.
     * Neutralize the handler until our own finalize sets it back once the
     * round trip actually completes. */
    r->write_event_handler = ngx_http_request_empty_handler;

    return NGX_AGAIN;
}

/* Reference: ngx_http_auth_jwt_validate_variable. Redis-confirmed decision
* order (ADR-0006/ADR-0012, not overridable by location config): all-nil is
* not-found, then enabled must be exactly "1", then auth_apikey_require. */
static ngx_int_t
ngx_http_auth_apikey_process_result(ngx_http_request_t *r,
    ngx_http_auth_apikey_loc_conf_t *alcf, ngx_http_auth_apikey_ctx_t *ctx)
{
    ngx_uint_t i;
    ngx_flag_t not_found;
    ngx_str_t enabled;
    ngx_http_auth_apikey_require_variable_t *req;
    ngx_http_upstream_t *u;

    /* ngx_http_auth_apikey_finalize_upstream_request() re-runs the phase
     * handler on every upstream outcome, including hard errors: it stores
     * the mapped status in u->state->status and re-enters here before
     * ctx->reply_parsed is ever set. fields_nil[] is untouched zero-init
     * in that case, which would otherwise read as "all nil" (not-found)
     * and mask the real error behind a 401. */
    if (!ctx->reply_parsed) {
        u = r->upstream;

        if (u && u->state && u->state->status) {
            return (ngx_int_t) u->state->status;
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    not_found = 1;

    for (i = 0; i < NGX_HTTP_AUTH_APIKEY_FIELDS; i++) {
        if (!ctx->fields_nil[i]) {
            not_found = 0;
            break;
        }
    }

    if (not_found) {
        return ngx_http_auth_apikey_unauthorized(r, alcf,
                                                 ctx->use_default_header);
    }

    enabled = ctx->fields[NGX_HTTP_AUTH_APIKEY_FIELD_ENABLED];

    if (ctx->fields_nil[NGX_HTTP_AUTH_APIKEY_FIELD_ENABLED]
        || enabled.len != 1
        || ngx_strncmp("1", enabled.data, enabled.len) != 0)
    {
        return ngx_http_auth_apikey_unauthorized(r, alcf,
                                                 ctx->use_default_header);
    }

    ctx->verified = 1;

    if (alcf->requires) {
        req = alcf->requires->elts;

        for (i = 0; i < alcf->requires->nelts; i++) {
            ngx_str_t value = ngx_null_string;

            if (ngx_http_complex_value(r, &req[i].value, &value) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (!value.data || value.len == 0
                || ngx_strncmp("0", value.data, value.len) == 0)
            {
                return req[i].error;
            }
        }
    }

    return NGX_OK;
}

/* Reference: ngx_http_ratelimit_create_request. HMGET, fixed field order
 * (ADR-0012): user_id, scope, quota, enabled. */
static ngx_int_t
ngx_http_auth_apikey_create_request(ngx_http_request_t *r)
{
    ngx_buf_t *b;
    ngx_str_t argv[6];
    ngx_chain_t *cl;
    ngx_http_auth_apikey_ctx_t *ctx;

    ctx = ngx_http_auth_apikey_get_module_ctx(r);

    ngx_str_set(&argv[0], "HMGET");
    argv[1] = ctx->hash_key;
    ngx_str_set(&argv[2], "user_id");
    ngx_str_set(&argv[3], "scope");
    ngx_str_set(&argv[4], "quota");
    ngx_str_set(&argv[5], "enabled");

    if (ngx_http_auth_apikey_build_command(r, &b, argv, 6) != NGX_OK) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;
    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_apikey_reinit_request(ngx_http_request_t *r)
{
    r->upstream->process_header = ngx_http_auth_apikey_process_header;
    r->upstream->read_event_handler =
        ngx_http_auth_apikey_read_header_handler;

    return NGX_OK;
}

/* Reference: ngx_http_ratelimit_process_header. Consumes only the leading
 * '*' of the RESP array; ngx_http_auth_apikey_process_reply (reply.c) reads
 * the element count and the four fields that follow. */
static ngx_int_t
ngx_http_auth_apikey_process_header(ngx_http_request_t *r)
{
    u_char *p;
    ngx_str_t line, sanitized;
    ngx_http_upstream_t *u;

    u = r->upstream;

    if (u->buffer.last - u->buffer.pos < 1) {
        return NGX_AGAIN;
    }

    if (*u->buffer.pos == '*') {
        u->buffer.pos++;
        u->state->status = NGX_HTTP_OK;
        return NGX_OK;
    }

    if (*u->buffer.pos == '-') {
        for (p = u->buffer.pos; p < u->buffer.last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        if (p == u->buffer.last) {
            return NGX_AGAIN;
        }

        line.data = u->buffer.pos;
        line.len = p - u->buffer.pos;

        sanitized = ngx_http_auth_apikey_sanitize_log_str(r, &line);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_apikey: redis error reply: \"%V\"", &sanitized);

        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "auth_apikey: unexpected redis reply type");

    return NGX_ERROR;
}

static void
ngx_http_auth_apikey_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http auth apikey request");
}

static void
ngx_http_auth_apikey_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_auth_apikey_ctx_t *ctx;

    ctx = ngx_http_auth_apikey_get_module_ctx(r);
    if (ctx == NULL) {
        return;
    }

    ctx->finalized = 1;
}

static ngx_int_t
ngx_http_auth_apikey_filter_init(void *data)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_apikey_filter(void *data, ssize_t bytes)
{
    ngx_http_auth_apikey_ctx_t *ctx = data;

    return ngx_http_auth_apikey_process_reply(ctx, bytes);
}
