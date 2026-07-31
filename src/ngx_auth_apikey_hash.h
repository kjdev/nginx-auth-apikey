#ifndef NGX_AUTH_APIKEY_HASH_H
#define NGX_AUTH_APIKEY_HASH_H

#include <ngx_config.h>
#include <ngx_core.h>

/* SHA-256 digest length in bytes (Redis key is hex(sha256(K)), ADR-0005) */
#define NGX_AUTH_APIKEY_SHA256_LEN  32

/*
 * Compute SHA-256 over data[0..len) and write the 32-byte digest to out.
 * out must point to a buffer of at least NGX_AUTH_APIKEY_SHA256_LEN bytes.
 * A len of 0 is valid (digest of the empty input); data may be NULL only
 * when len is 0.
 *
 * Returns NGX_OK on success, NGX_ERROR on failure (OpenSSL error,
 * out == NULL, or data == NULL with len > 0).
 */
ngx_int_t ngx_auth_apikey_hash_sha256(const u_char *data, size_t len,
    u_char *out);

#endif /* NGX_AUTH_APIKEY_HASH_H */
