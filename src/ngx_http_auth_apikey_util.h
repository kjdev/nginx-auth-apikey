#ifndef NGX_HTTP_AUTH_APIKEY_UTIL_H
#define NGX_HTTP_AUTH_APIKEY_UTIL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Maximum bytes copied into the sanitized log buffer (rules/nginx-module-c.md:
 * never log the raw API key or its hash, but Redis-derived strings are safe
 * once truncated and stripped of control bytes). */
#define NGX_HTTP_AUTH_APIKEY_LOG_SANITIZE_MAX  128

ngx_http_upstream_srv_conf_t *ngx_http_auth_apikey_upstream_add(
    ngx_http_request_t *r, ngx_url_t *url);

ngx_int_t ngx_http_auth_apikey_build_command(ngx_http_request_t *r,
    ngx_buf_t **b, ngx_str_t *argv, ngx_uint_t argc);

/* Truncates src to NGX_HTTP_AUTH_APIKEY_LOG_SANITIZE_MAX bytes and replaces
 * non-printable bytes with '.'. */
ngx_str_t ngx_http_auth_apikey_sanitize_log_str(ngx_http_request_t *r,
    ngx_str_t *src);

#endif /* NGX_HTTP_AUTH_APIKEY_UTIL_H */
