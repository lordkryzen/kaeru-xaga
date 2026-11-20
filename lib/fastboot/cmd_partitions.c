//
// SPDX-FileCopyrightText: 2025-2026 Roger Ortiz <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <lib/debug.h>
#include <lib/fastboot.h>
#include <lib/storage.h>

void cmd_partitions(const char* arg, void* data, unsigned sz) {
    int count = storage_part_count();
    if (!count) {
        fastboot_fail("Partition table is not available");
        return;
    }

    char line[FASTBOOT_INFO_MAX + 1];

#ifdef CONFIG_NATIVE_BIO_STORAGE
    fastboot_info("BIO device/partition    offset    blocks");
#else
    fastboot_info("name                    start     blocks");
#endif
    for (int i = 0; i < count; i++) {
        const struct part_info* part = storage_part_get(i);
        if (!part) {
            break;
        }

#ifdef CONFIG_ARCH_ARM64
        npf_snprintf(line, sizeof(line), "%-20s %9llx %10llx", part->name,
                     (unsigned long long)part->start_block, (unsigned long long)part->size_blocks);
#else
        npf_snprintf(line, sizeof(line), "%-20s %9u %10u", part->name,
                     (unsigned)part->start_block, (unsigned)part->size_blocks);
#endif
        fastboot_info(line);
    }

    fastboot_okay("");
}

FASTBOOT_CMD(partitions, "oem partitions", cmd_partitions, 1);
