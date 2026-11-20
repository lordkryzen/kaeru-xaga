//
// SPDX-FileCopyrightText: 2025-2026 Roger Ortiz <roger@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <lib/fastboot.h>

#ifdef CONFIG_FASTBOOT_OEM_TABLE
#include <lib/oem_table.h>
#endif

#if defined(CONFIG_FASTBOOT_STYLE_COMBINED)

static void (*const _send_response)(const char* status, const char* fmt, ...) =
        (void*)ARCH_FN(CONFIG_FASTBOOT_SEND_RESPONSE_ADDRESS);

static void (*const _send_info)(const char* status, const char* fmt, ...) =
        (void*)ARCH_FN(CONFIG_FASTBOOT_SEND_INFO_ADDRESS);

void fastboot_okay(const char* reason) {
    _send_response("OKAY", reason);
}

void fastboot_fail(const char* reason) {
    _send_response("FAIL", reason);
}

void fastboot_info(const char* reason) {
    _send_info("INFO", reason);
}

void fastboot_register(const char* prefix,
                       void (*handle)(const char* arg, void* data, unsigned sz),
                       unsigned char security_enabled) {
    (void)security_enabled;
#ifdef CONFIG_FASTBOOT_OEM_TABLE
    oem_table_add_command(prefix, handle);
#else
    (void)prefix;
    (void)handle;
#endif
}

void fastboot_publish(const char* name, const char* value) {
    (void)name;
    (void)value;
}

#elif defined(CONFIG_FASTBOOT_STYLE_STANDARD)

void fastboot_okay(const char* reason) {
    ((void (*)(const char*))ARCH_FN(CONFIG_FASTBOOT_OKAY_ADDRESS))(reason);
}

void fastboot_fail(const char* reason) {
    ((void (*)(const char*))ARCH_FN(CONFIG_FASTBOOT_FAIL_ADDRESS))(reason);
}

void fastboot_info(const char* reason) {
    ((void (*)(const char*))ARCH_FN(CONFIG_FASTBOOT_INFO_ADDRESS))(reason);
}

void fastboot_register(const char* prefix,
                       void (*handle)(const char* arg, void* data, unsigned sz),
                       unsigned char security_enabled) {
    ((void (*)(const char*, void (*)(const char*, void*, unsigned), unsigned,
               unsigned))ARCH_FN(CONFIG_FASTBOOT_REGISTER_ADDRESS))(prefix, handle,
                                                                 security_enabled, 0);
}

void fastboot_publish(const char* name, const char* value) {
    ((void (*)(const char*, const char*))ARCH_FN(CONFIG_FASTBOOT_PUBLISH_ADDRESS))(name, value);
}

#else
#error "No fastboot response style selected."
#endif
