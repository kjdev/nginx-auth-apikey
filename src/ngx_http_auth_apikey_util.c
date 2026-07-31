#include "ngx_http_auth_apikey_util.h"

static size_t ngx_http_auth_apikey_get_num_size(uint64_t i);

/* Reference: ngx_http_ratelimit_upstream_add */
ngx_http_upstream_srv_conf_t *
ngx_http_auth_apikey_upstream_add(ngx_http_request_t *r, ngx_url_t *url)
{
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_uint_t i;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != url->host.len
            || ngx_strncasecmp(uscfp[i]->host.data, url->host.data,
                               url->host.len) != 0)
        {
            continue;
        }

        if (uscfp[i]->port != url->port) {
            continue;
        }

#if defined(nginx_version) && nginx_version < 1011006
        if (uscfp[i]->default_port && url->default_port
            && uscfp[i]->default_port != url->default_port)
        {
            continue;
        }
#endif

        return uscfp[i];
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth_apikey: no upstream found: %V", &url->host);

    return NULL;
}

static size_t
ngx_http_auth_apikey_get_num_size(uint64_t i)
{
    size_t n = 0;

    do {
        i = i / 10;
        n++;
    } while (i > 0);

    return n;
}

/* Reference: ngx_http_ratelimit_build_command. Encodes a RESP array of bulk
 * strings: "*<argc>\r\n" then "$<len>\r\n<data>\r\n" for each argument. */
ngx_int_t
ngx_http_auth_apikey_build_command(ngx_http_request_t *r, ngx_buf_t **b,
    ngx_str_t *argv, ngx_uint_t argc)
{
    size_t len;
    u_char *p;
    ngx_uint_t i;

    len = sizeof("*") - 1;
    len += ngx_http_auth_apikey_get_num_size(argc);
    len += sizeof("\r\n") - 1;

    for (i = 0; i < argc; i++) {
        len += sizeof("$") - 1;
        len += ngx_http_auth_apikey_get_num_size(argv[i].len);
        len += sizeof("\r\n") - 1;
        len += argv[i].len;
        len += sizeof("\r\n") - 1;
    }

    *b = ngx_create_temp_buf(r->pool, len);
    if (*b == NULL) {
        return NGX_ERROR;
    }

    p = (*b)->last;

    *p++ = '*';
    p = ngx_sprintf(p, "%ui", argc);
    *p++ = CR;
    *p++ = LF;

    for (i = 0; i < argc; i++) {
        *p++ = '$';
        p = ngx_sprintf(p, "%uz", argv[i].len);
        *p++ = CR;
        *p++ = LF;
        p = ngx_copy(p, argv[i].data, argv[i].len);
        *p++ = CR;
        *p++ = LF;
    }

    if (p - (*b)->pos != (ssize_t) len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_apikey: buffer error %uz != %uz",
                      (size_t) (p - (*b)->pos), len);

        return NGX_ERROR;
    }

    (*b)->last = p;

    return NGX_OK;
}

/* Reference: ngx_http_ratelimit_sanitize_log_str. A compromised or MITM'd
 * Redis peer otherwise controls raw bytes that "%V" writes verbatim into the
 * error log, letting embedded CR/LF forge extra log lines. */
ngx_str_t
ngx_http_auth_apikey_sanitize_log_str(ngx_http_request_t *r, ngx_str_t *src)
{
    u_char *dst;
    ngx_uint_t i, n;
    ngx_str_t out;

    n = src->len;
    if (n > NGX_HTTP_AUTH_APIKEY_LOG_SANITIZE_MAX) {
        n = NGX_HTTP_AUTH_APIKEY_LOG_SANITIZE_MAX;
    }

    dst = ngx_pnalloc(r->pool, n);
    if (dst == NULL) {
        ngx_str_null(&out);
        return out;
    }

    for (i = 0; i < n; i++) {
        dst[i] = (src->data[i] >= 0x20 && src->data[i] < 0x7f)
                 ? src->data[i] : '.';
    }

    out.data = dst;
    out.len = n;

    return out;
}
