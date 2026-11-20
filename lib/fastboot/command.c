//
// SPDX-FileCopyrightText: 2025-2026 Roger Ortiz <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <lib/debug.h>
#include <lib/fastboot.h>
#include <main/main.h>

extern const struct fastboot_command __fastboot_cmds_start[];
extern const struct fastboot_command __fastboot_cmds_end[];

void fastboot_register_commands(void) {
    for (const struct fastboot_command* c = __fastboot_cmds_start; c < __fastboot_cmds_end; c++) {
        /* AArch64 startup already applied ELF RELATIVE relocations. */
#ifdef CONFIG_ARCH_ARM64
        const uintptr_t delta = 0;
#else
        const uintptr_t delta = kaeru_reloc_delta;
#endif
        const char* prefix = (const char*)((uintptr_t)c->prefix + delta);
        void (*handle)(const char*, void*, unsigned) =
                (void (*)(const char*, void*, unsigned))((uintptr_t)c->handle + delta);

        printf("Registering fastboot command '%s' at 0x%08X\n", prefix,
               (unsigned)(uintptr_t)handle);

        fastboot_register(prefix, handle, c->security);
    }
}
