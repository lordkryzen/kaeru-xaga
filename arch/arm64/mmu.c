/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <arch/cache.h>

/* Exact xaga EL1 mapping: 4 KiB granules, 48-bit TTBR1 kernel addresses. */
static volatile uint64_t *leaf_for(uintptr_t address) {
    uint64_t root, tcr;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(root));
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
    if (((tcr >> 16) & 63) != 16 || ((tcr >> 30) & 3) != 2 ||
        address >> 48 != 0xffff) return NULL;
    for (int shift = 39; shift >= 12; shift -= 9) {
        uintptr_t table = (root & 0x0000fffffffff000ULL) | 0xffff000000000000ULL;
        volatile uint64_t *entry = (volatile uint64_t *)(table + ((address >> shift) & 511) * 8);
        root = *entry;
        if ((root & 3) != 3) return NULL;
        if (shift == 12) return entry;
    }
    return NULL;
}

static void update_leaf(volatile uint64_t *leaf, uint64_t value) {
    *leaf = value;
    __asm__ volatile("dc cvac, %0\n dsb ishst\n tlbi vmalle1is\n dsb ish\n isb"
                     : : "r"(leaf) : "memory");
}

bool arch_patch_bytes(uintptr_t address, const void *source, size_t length) {
    const unsigned char *input = source;
    while (length) {
        volatile uint64_t *leaf = leaf_for(address);
        if (!leaf) return false;
        uint64_t original = *leaf;
        size_t chunk = 4096 - (address & 4095);
        if (chunk > length) chunk = length;
        /* Keep WXN enabled: writable native text is temporarily non-executable.
         * This helper executes from the separate resident RX code mapping. */
        if (original & 128) update_leaf(leaf, original & ~128ULL);
        for (size_t i = 0; i < chunk; ++i)
            ((volatile unsigned char *)address)[i] = input[i];
        arch_sync_cache_range(address, chunk);
        if (original & 128) update_leaf(leaf, original);
        address += chunk;
        input += chunk;
        length -= chunk;
    }
    return true;
}
