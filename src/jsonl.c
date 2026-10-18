/*
 * jsonl.c — see jsonl.h.
 */

#include "jsonl.h"

#include <stdio.h>

/*
 * Length of the well-formed UTF-8 sequence starting at s (RFC 3629: no
 * overlongs, no surrogates, max U+10FFFF), or 0 if ill-formed.
 */
static size_t utf8_seq_len(const unsigned char *s, size_t avail)
{
    unsigned char c = s[0];
    size_t need;
    unsigned char lo = 0x80, hi = 0xBF;

    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF)
        need = 2;
    else if (c >= 0xE0 && c <= 0xEF) {
        need = 3;
        if (c == 0xE0)
            lo = 0xA0;           /* overlong */
        else if (c == 0xED)
            hi = 0x9F;           /* UTF-16 surrogates */
    } else if (c >= 0xF0 && c <= 0xF4) {
        need = 4;
        if (c == 0xF0)
            lo = 0x90;           /* overlong */
        else if (c == 0xF4)
            hi = 0x8F;           /* > U+10FFFF */
    } else
        return 0;

    if (avail < need)
        return 0;
    if (s[1] < lo || s[1] > hi)
        return 0;
    for (size_t i = 2; i < need; ++i) {
        if (s[i] < 0x80 || s[i] > 0xBF)
            return 0;
    }
    return need;
}

int pp_json_escape(const char *src, size_t n, char *dst, size_t dst_size)
{
    const unsigned char *s = (const unsigned char *)src;
    size_t out = 0, i = 0;
    int valid = 1;

    if (dst_size < PP_JSON_ESCAPED_MAX(n)) {
        if (dst_size > 0)
            dst[0] = '\0';
        return 0;
    }

    while (i < n) {
        unsigned char c = s[i];

        if (c == '"' || c == '\\') {
            dst[out++] = '\\';
            dst[out++] = (char)c;
            ++i;
        } else if (c < 0x20) {
            out += (size_t)snprintf(dst + out, dst_size - out, "\\u%04x", (unsigned)c);
            ++i;
        } else {
            size_t len = utf8_seq_len(s + i, n - i);
            if (len == 0) {
                dst[out++] = (char)0xEF;
                dst[out++] = (char)0xBF;
                dst[out++] = (char)0xBD;
                valid = 0;
                ++i;
            } else {
                for (size_t k = 0; k < len; ++k)
                    dst[out++] = (char)s[i + k];
                i += len;
            }
        }
    }
    dst[out] = '\0';
    return valid;
}
