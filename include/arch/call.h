/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#pragma once
#include <stdint.h>
#ifdef CONFIG_ARCH_ARM64
#define ARCH_FN(address) ((uintptr_t)(address))
#else
#define ARCH_FN(address) ((uintptr_t)(address) | 1U)
#endif
