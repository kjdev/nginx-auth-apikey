#ifndef NGX_HTTP_AUTH_APIKEY_MODULE_H
#define NGX_HTTP_AUTH_APIKEY_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_module_t ngx_http_auth_apikey_module;

/* One "auth_apikey_require $var ... [error=code];" condition. */
typedef struct {
    ngx_http_complex_value_t  value;
    ngx_int_t                 error;
} ngx_http_auth_apikey_require_variable_t;

typedef struct {
    ngx_flag_t                enabled;
    ngx_str_t                 realm;

    /* NGX_CONF_UNSET selects the default credential source
    * (Authorization: ApiKey <key>); otherwise the index of the
    * variable named by "auth_apikey ... key=$variable". */
    ngx_int_t                 key_variable;

    /* of ngx_http_auth_apikey_require_variable_t, evaluated in order,
     * all conditions ANDed. */
    ngx_array_t              *requires;

    /* "auth_apikey_pass $variable" target, compiled when the upstream
     * name is not known at configuration time. */
    ngx_http_complex_value_t *complex_target;

    ngx_http_upstream_conf_t  upstream;
} ngx_http_auth_apikey_loc_conf_t;

#endif /* NGX_HTTP_AUTH_APIKEY_MODULE_H */
