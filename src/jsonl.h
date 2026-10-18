/*
 * jsonl.h — JSON string escaping that always produces valid UTF-8.
 */
#ifndef JSONL_H
#define JSONL_H

#include <stddef.h>

/*
 * Worst-case output size for n input bytes: every byte may become a 6-byte
 * \u00XX escape or a 3-byte U+FFFD replacement; 6 bounds both.
 */
#define PP_JSON_ESCAPED_MAX(n) ((n) * 6 + 1)

/*
 * Writes a JSON string body (without quotes) for the n bytes at src into dst.
 *   - '"' and '\\' are backslash-escaped;
 *   - bytes < 0x20 become \u00XX;
 *   - well-formed UTF-8 sequences are copied unchanged;
 *   - each byte of an ill-formed sequence becomes U+FFFD (EF BF BD).
 * Returns 1 if src was valid UTF-8, 0 if any replacement was made.
 * dst_size must be at least PP_JSON_ESCAPED_MAX(n).
 */
int pp_json_escape(const char *src, size_t n, char *dst, size_t dst_size);

#endif /* JSONL_H */
