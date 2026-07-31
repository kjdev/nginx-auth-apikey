#ifndef NGX_HTTP_AUTH_APIKEY_HANDLER_H
#define NGX_HTTP_AUTH_APIKEY_HANDLER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Fixed HMGET field order: user_id, scope, quota, enabled (ADR-0012). */
#define NGX_HTTP_AUTH_APIKEY_FIELD_USER_ID  0
#define NGX_HTTP_AUTH_APIKEY_FIELD_SCOPE    1
#define NGX_HTTP_AUTH_APIKEY_FIELD_QUOTA    2
#define NGX_HTTP_AUTH_APIKEY_FIELD_ENABLED  3
#define NGX_HTTP_AUTH_APIKEY_FIELDS         4

typedef struct {
    ngx_http_request_t *request;

    ngx_str_t           key; /* raw API key extracted from the request */
    ngx_str_t           hash_key; /* "apikey:cred:<sha256 hex>" */

    ngx_flag_t          use_default_header; /* key came from the Authorization header */

    /* RESP reply parser state, preserved across NGX_AGAIN. */
    ngx_uint_t          state;
    ngx_uint_t          field;
    ngx_uint_t          len_accum;
    ngx_flag_t          len_neg;
    ngx_uint_t          data_left;

    ngx_str_t           fields[NGX_HTTP_AUTH_APIKEY_FIELDS];
    ngx_flag_t          fields_nil[NGX_HTTP_AUTH_APIKEY_FIELDS];

    ngx_flag_t          finalized;
    ngx_flag_t          reply_parsed;

    /* Set once the enabled check has passed; $apikey_* stay not_found until
     * then, so an internal redirect never observes a half-decided reply. */
    ngx_flag_t          verified;
} ngx_http_auth_apikey_ctx_t;

ngx_int_t ngx_http_auth_apikey_handler(ngx_http_request_t *r);

/*
 * Recovers ctx after an internal redirect wipes r->ctx, by walking the pool
 * cleanup chain for the handler address left behind
 * (ngx_http_auth_jwt_get_module_ctx() equivalent).
 */
ngx_http_auth_apikey_ctx_t *ngx_http_auth_apikey_get_module_ctx(
    ngx_http_request_t *r);

#endif /* NGX_HTTP_AUTH_APIKEY_HANDLER_H */
