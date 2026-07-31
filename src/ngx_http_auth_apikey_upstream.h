#ifndef NGX_HTTP_AUTH_APIKEY_UPSTREAM_H
#define NGX_HTTP_AUTH_APIKEY_UPSTREAM_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Reference: ngx_http_upstream_finalize_request. The first finalize on a
 * request must return NGX_DONE (see handler.c's ngx_http_auth_apikey_
 * finalize_request) so the phase engine re-enters exactly once and emits the
 * response exactly once. */
void ngx_http_auth_apikey_finalize_upstream_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc);

/* Reference: ngx_http_upstream_process_header. Reads the RESP header/body
 * from the Redis connection, driving u->process_header and u->input_filter. */
void ngx_http_auth_apikey_read_header_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u);

#endif /* NGX_HTTP_AUTH_APIKEY_UPSTREAM_H */
