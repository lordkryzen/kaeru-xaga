//
// SPDX-FileCopyrightText: 2025 Shomy <shomy@shomy.is-a.dev>
//                         2025 Roger Ortiz <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <stage1/memory.h>

void* malloc(size_t size) {
    return ((void* (*)(size_t))ARCH_FN(CONFIG_MALLOC_ADDRESS))(size);
}

void free(void* ptr) {
    ((void (*)(void*))ARCH_FN(CONFIG_FREE_ADDRESS))(ptr);
}