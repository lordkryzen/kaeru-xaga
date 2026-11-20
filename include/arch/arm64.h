/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <arch/cache.h>
#include <lib/string.h>
bool arch_patch_bytes(uintptr_t address, const void *source, size_t length);

#define ARM_MODE(lr) "AArch64"
#define READ_SP(var) asm volatile("mov %0, sp" : "=r"(var))
#define READ_LR(var) asm volatile("mov %0, x30" : "=r"(var))
#define READ_VBAR(var) asm volatile("mrs %0, vbar_el1" : "=r"(var))

/* These helpers deliberately use AAPCS64 scratch x16 for indirect jumps. */
static inline bool arm64_patch_branch(uintptr_t site, uintptr_t target, bool link) {
    intptr_t offset = (intptr_t)target - (intptr_t)site;
    if ((site | target) & 3 || offset < -0x8000000L || offset >= 0x8000000L)
        return false;
    uint32_t instruction = (link ? 0x94000000U : 0x14000000U) | ((offset >> 2) & 0x03ffffff);
    return arch_patch_bytes(site, &instruction, 4);
}
static inline bool arm64_patch_call(uintptr_t site, uintptr_t target) {
    return arm64_patch_branch(site, target, true);
}

static inline void arm64_hook(uintptr_t site, const void *target) {
    uint32_t p[4];
    p[0] = 0x58000050; /* ldr x16, PC+8 */
    p[1] = 0xd61f0200; /* br x16 */
    uintptr_t value = (uintptr_t)target;
    p[2] = (uint32_t)value;
    p[3] = (uint32_t)(value >> 32);
    arch_patch_bytes(site, p, sizeof(p));
}

static inline void arm64_force_return(uintptr_t site, unsigned value) {
    uint32_t p[2];
    p[0] = 0x52800000U | ((value & 0xffff) << 5); /* movz w0, value */
    p[1] = 0xd65f03c0; /* ret */
    arch_patch_bytes(site, p, sizeof(p));
}

#define WRITE64(addr, value) do { \
    *(volatile uint64_t *)(uintptr_t)(addr) = (uint64_t)(value); \
    arch_sync_cache_range((uintptr_t)(addr), 8); \
} while (0)
#define READ64(addr) (*(volatile uint64_t *)(uintptr_t)(addr))
#define FORCE_RETURN(addr, value) arm64_force_return((uintptr_t)(addr), (value))
#define NOP(addr, count) do { \
    for (size_t _i = 0; _i < (count); ++_i) \
        ((volatile uint32_t *)(uintptr_t)(addr))[_i] = 0xd503201f; \
    arch_sync_cache_range((uintptr_t)(addr), (count) * 4); \
} while (0)
