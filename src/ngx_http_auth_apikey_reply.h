#ifndef NGX_HTTP_AUTH_APIKEY_REPLY_H
#define NGX_HTTP_AUTH_APIKEY_REPLY_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_auth_apikey_handler.h"

/* Parses an HMGET reply: a RESP array of NGX_HTTP_AUTH_APIKEY_FIELDS bulk
 * strings (each possibly nil). Returns NGX_OK once fully parsed, NGX_AGAIN
 * if more bytes are needed, NGX_ERROR on a malformed reply. */
ngx_int_t ngx_http_auth_apikey_process_reply(ngx_http_auth_apikey_ctx_t *ctx,
    ssize_t bytes);

#endif /* NGX_HTTP_AUTH_APIKEY_REPLY_H */
