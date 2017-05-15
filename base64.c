/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <stdlib.h>
#include <string.h>

#include "base64.h"

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char base64_urlsafe_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
char* base64_table_encode(const unsigned char *table, const unsigned char *src, size_t len, size_t *out_len)
{
    size_t olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
    olen += olen / 72; /* line feeds */
    olen++; /* nul termination */
    if (olen < len) {
        return NULL; /* integer overflow */
    }
    unsigned char *out = malloc(olen);
    if (!out) {
        return NULL;
    }

    const unsigned char *end = src + len;
    const unsigned char *in = src;
    unsigned char *pos = out;
    while (end - in >= 3) {
        *pos++ = table[in[0] >> 2];
        *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = table[(in[0] & 0x03) << 4];
        } else {
            *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = table[(in[1] & 0x0f) << 2];
        }
    }

    *pos = '\0';
    if (out_len) {
        *out_len = pos - out;
    }
    return (char*)out;
}

char* base64_encode(const unsigned char *src, size_t len, size_t *out_len)
{
    return base64_table_encode(base64_table, src, len, out_len);
}

char* base64_urlsafe_encode(const unsigned char *src, size_t len, size_t *out_len)
{
    return base64_table_encode(base64_urlsafe_table, src, len, out_len);
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char* base64_decode(const unsigned char *src, size_t len, size_t *out_len)
{
    size_t i;

    static unsigned char dtable[256] = {0};
    if (!dtable[0]) {
        memset(dtable, 0x80, 256);
        for (i = 0; i < sizeof(base64_table) - 1; i++) {
            dtable[base64_table[i]] = (unsigned char)i;
            if (base64_urlsafe_table[i] != base64_table[i]) {
                dtable[base64_urlsafe_table[i]] = (unsigned char)i;
            }
        }
        dtable['='] = 0;
    }

    size_t count = 0;
    for (i = 0; i < len; i++) {
        if (dtable[src[i]] != 0x80) {
            count++;
        }
    }

    if (count == 0 || count % 4) {
        return NULL;
    }

    size_t olen = count / 4 * 3;
    unsigned char *out = malloc(olen);
    if (!out) {
        return NULL;
    }
    unsigned char *pos = out;

    count = 0;
    unsigned char block[4];
    for (i = 0; i < len; i++) {
        unsigned char tmp = dtable[src[i]];
        if (tmp == 0x80) {
            continue;
        }

        block[count] = tmp;
        count++;
        if (count == 4) {
            *pos++ = (block[0] << 2) | (block[1] >> 4);
            *pos++ = (block[1] << 4) | (block[2] >> 2);
            *pos++ = (block[2] << 6) | block[3];
            count = 0;
        }
    }

    *out_len = pos - out;
    return out;
}
