/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stddef.h>
void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dest;
}
void *memset(void *dest, int value, size_t n) {
    unsigned char *d = dest;
    while (n--) *d++ = (unsigned char)value;
    return dest;
}
void *memchr(const void *src, int value, size_t n) {
    const unsigned char *s = src;
    while (n--) {
        if (*s == (unsigned char)value) return (void *)s;
        ++s;
    }
    return NULL;
}
