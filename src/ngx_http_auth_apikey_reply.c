#include "ngx_http_auth_apikey_reply.h"

/* Accumulate one decimal digit into *val, failing closed if the running
 * value would exceed NGX_MAX_INT_T_VALUE. Guards against a malformed or
 * hostile reply overflowing the length before an allocation is sized from
 * it. */
static ngx_int_t
ngx_http_auth_apikey_accum_digit(ngx_uint_t *val, u_char ch)
{
    ngx_uint_t d = ch - '0';

    if (*val > (NGX_MAX_INT_T_VALUE - d) / 10) {
        return NGX_ERROR;
    }

    *val = *val * 10 + d;

    return NGX_OK;
}

/* Parses "*4\r\n" followed by NGX_HTTP_AUTH_APIKEY_FIELDS bulk strings
 * ("$<len>\r\n<data>\r\n") or nils ("$-1\r\n"), in the fixed HMGET order
 * user_id/scope/quota/enabled. The leading '*' is consumed by
 * u->process_header; this parser starts at the element count digit. */
ngx_int_t
ngx_http_auth_apikey_process_reply(ngx_http_auth_apikey_ctx_t *ctx,
    ssize_t bytes)
{
    ngx_buf_t *b;
    ngx_http_upstream_t *u;
    ngx_str_t *field;
    u_char ch, *p;

    enum {
        sw_start = 0,
        sw_count_lf,
        sw_field_type,
        sw_field_len,
        sw_field_len_lf,
        sw_field_data,
        sw_field_data_cr,
        sw_field_data_lf
    } state;

    u = ctx->request->upstream;
    b = &u->buffer;

    state = ctx->state;

    b->pos = b->last;
    b->last += bytes;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:
            /* HMGET always requests exactly NGX_HTTP_AUTH_APIKEY_FIELDS
             * keys, so the array length is always this fixed digit. */
            if (ch != '0' + NGX_HTTP_AUTH_APIKEY_FIELDS) {
                return NGX_ERROR;
            }
            state = sw_count_lf;
            break;

        case sw_count_lf:
            switch (ch) {
            case CR:
                break;
            case LF:
                state = sw_field_type;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_field_type:
            if (ch != '$') {
                return NGX_ERROR;
            }
            ctx->len_accum = 0;
            ctx->len_neg = 0;
            state = sw_field_len;
            break;

        case sw_field_len:
            switch (ch) {
            case '-':
                ctx->len_neg = 1;
                break;
            case CR:
                state = sw_field_len_lf;
                break;
            default:
                if (ch < '0' || ch > '9') {
                    return NGX_ERROR;
                }

                if (ngx_http_auth_apikey_accum_digit(&ctx->len_accum, ch)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                break;
            }
            break;

        case sw_field_len_lf:
            if (ch != LF) {
                return NGX_ERROR;
            }

            field = &ctx->fields[ctx->field];

            if (ctx->len_neg) {
                ctx->fields_nil[ctx->field] = 1;
                field->len = 0;
                field->data = NULL;

                ctx->field++;

                if (ctx->field == NGX_HTTP_AUTH_APIKEY_FIELDS) {
                    goto done;
                }

                state = sw_field_type;
                break;
            }

            field->len = ctx->len_accum;

            if (field->len > 0) {
                field->data = ngx_pnalloc(ctx->request->pool, field->len);
                if (field->data == NULL) {
                    return NGX_ERROR;
                }

            } else {
                field->data = NULL;
            }

            ctx->data_left = field->len;
            state = (ctx->data_left == 0) ? sw_field_data_cr : sw_field_data;
            break;

        case sw_field_data:
            ctx->fields[ctx->field].data[
                ctx->fields[ctx->field].len - ctx->data_left] = ch;
            ctx->data_left--;

            if (ctx->data_left == 0) {
                state = sw_field_data_cr;
            }
            break;

        case sw_field_data_cr:
            if (ch != CR) {
                return NGX_ERROR;
            }
            state = sw_field_data_lf;
            break;

        case sw_field_data_lf:
            if (ch != LF) {
                return NGX_ERROR;
            }

            ctx->field++;

            if (ctx->field == NGX_HTTP_AUTH_APIKEY_FIELDS) {
                goto done;
            }

            state = sw_field_type;
            break;
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    /* A well-behaved Redis sends exactly one reply per request, but if the
     * buffer somehow holds trailing bytes past this reply, returning the
     * connection to the keepalive pool now would desync the next request
     * on reuse. */
    u->keepalive = (b->pos == b->last) ? 1 : 0;
    u->length = 0;

    ctx->reply_parsed = 1;

    return NGX_OK;
}
