//
// SPDX-FileCopyrightText: 2025-2026 Roger Ortiz <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <arch/arm.h>
#include <board_ops.h>
#include <main/main.h>

uintptr_t kaeru_reloc_delta;

void kaeru_late_init(const struct app_descriptor *app) {
    OPTIONAL_INIT(framebuffer_init);
    OPTIONAL_INIT(storage_init);

    board_late_init();
#ifdef CONFIG_ARCH_ARM64
    fastboot_register_commands();
#endif

    ((void (*)(const struct app_descriptor*))ARCH_FN(CONFIG_APP_ADDRESS))(app);
}

// We are now running in the heap, having been loaded and called by
// stage1 (the first stage loader).
//
// We want to patch the '.apps' entry in
// the rodata section of the bootloader to point to our late init
// function, so that we can take control before mt_boot_init() runs.
void kaeru_early_init(void) {
    OPTIONAL_INIT(sej_init);

    uintptr_t search_val = ARCH_FN(CONFIG_APP_ADDRESS);
    uintptr_t start = CONFIG_BOOTLOADER_BASE;
    uintptr_t end = CONFIG_BOOTLOADER_BASE + CONFIG_BOOTLOADER_SIZE;
    uintptr_t ptr_addr = 0;

    print_kaeru_info(printf);
    common_early_init();
    board_early_init();

    for (uintptr_t addr = start; addr + sizeof(uintptr_t) <= end; addr += sizeof(uintptr_t)) {
        if (*(volatile uintptr_t*)addr == search_val) {
            ptr_addr = addr;
            break;
        }
    }

    if (ptr_addr != 0) {
#ifdef CONFIG_ARCH_ARM64
        uintptr_t replacement = ARCH_FN(kaeru_late_init);
        arch_patch_bytes(ptr_addr, &replacement, sizeof(replacement));
#else
        *(volatile uintptr_t*)ptr_addr = ARCH_FN(kaeru_late_init);
        arch_clean_cache_range(ptr_addr, sizeof(uintptr_t));
#endif
    } else {
        // Not a critical failure, since the device should still boot
        // but I'm sure users will appreciate some feedback about it.
        printf("Failed to patch mt_init_boot() pointer\n");
        printf("kaeru won't be able to run its late init!\n");
    }

    ((void (*)(void))ARCH_FN(CONFIG_PLATFORM_INIT_ADDRESS))();
}
