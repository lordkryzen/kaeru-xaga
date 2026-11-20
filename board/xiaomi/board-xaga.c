/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <board_ops.h>
#include <lib/storage.h>

/* Native addresses are tied to the stock image hash in patch_arm64.py. */
static bool environment_ready;
static bool late_ready;
extern void xaga_getvar_trampoline(const char *, void *, unsigned);
extern void cmd_getvar(const char *, void *, unsigned);

static void xaga_select_boot_mode(void) {
    ((void (*)(void))CONFIG_BOOT_SELECT_ADDRESS)();
    volatile uint8_t *mode = (volatile uint8_t *)CONFIG_SELECTED_BOOTMODE_ADDRESS;
    if (*mode == BOOTMODE_RECOVERY &&
        ((bool (*)(unsigned))CONFIG_KEY_DETECT_ADDRESS)(1)) {
        *mode = BOOTMODE_FASTBOOT;
        printf("kaeru: fastboot key overrides recovery request\n");
    }
    /* Native app dispatch uses a separate byte from the platform mode word.
     * Keep lock-state and recovery hooks consistent with the selected app.
     */
    if (*mode == BOOTMODE_FASTBOOT || *mode == BOOTMODE_RECOVERY)
        set_bootmode(*mode);
}

static int xaga_avb_slot_verify(void *ops, const char *const *partitions,
                                const char *suffix, unsigned flags,
                                unsigned hashtree_mode, void **slot_data) {
    /* Image-auth bypass skips rollback-table initialization. Restore it after
     * the native OTP-update stage, before AVB reads rollback indexes.
     * This initializer reads OTP and updates RAM; it does not program OTP.
     */
    int ret = ((int (*)(void))CONFIG_OTP_VERSION_INIT_ADDRESS)();
    if (ret) {
        *slot_data = NULL;
        printf("kaeru: OTP version init failed: 0x%x\n", ret);
        return 2; /* AVB_SLOT_VERIFY_RESULT_ERROR_IO */
    }
    ret = ((int (*)(void *, const char *const *, const char *, unsigned,
                    unsigned, void **))CONFIG_AVB_SLOT_VERIFY_ADDRESS)(
                        ops, partitions, suffix, flags, hashtree_mode, slot_data);
    /* Native load_vfy_boot masks this result when allow-error is enabled. */
    printf("kaeru: avb_slot_verify ret=%d slot_data=%p\n", ret, *slot_data);
    return ret;
}

static int xaga_get_lock_state(uint32_t *state) {
    /* Native flash/erase handlers must see unlocked in bootloader fastboot. */
    if (get_bootmode() == BOOTMODE_FASTBOOT) {
        *state = LKS_UNLOCK;
        return 0;
    }
    return get_lock_state(state);
}

void xaga_original_getvar(const char *arg, void *data, unsigned size) {
    xaga_getvar_trampoline(arg, data, size);
}

static void xaga_env_init(void) {
    ((void (*)(void))CONFIG_ENV_INIT_ADDRESS)();
    environment_ready = true;
    arm64_hook(CONFIG_GET_LOCK_STATE_ADDRESS, xaga_get_lock_state);
    fastboot_publish("is-spoofing", is_spoofing_enabled() ? "1" : "0");
}

static void xaga_set_boot_state(unsigned state) {
    if (environment_ready && state == 2 && is_spoofing_enabled() &&
        get_bootmode() != BOOTMODE_RECOVERY)
        state = 0;
    *(volatile unsigned *)CONFIG_AVB_BOOT_STATE_ADDRESS = state;
}

/* Avoid accessing uninitialized native environment buffers. */
void board_early_init(void) {
    printf("kaeru: xaga AArch64 port by kryzen\n");
    arm64_force_return(CONFIG_VFY_POLICY_ADDRESS, 0);
    if (!arm64_patch_call(CONFIG_ENV_INIT_CALLER, (uintptr_t)xaga_env_init))
        printf("kaeru: environment hook out of branch range\n");
    arm64_patch_branch(CONFIG_AVB_SET_BOOT_STATE_ADDRESS,
                       (uintptr_t)xaga_set_boot_state, false);
}

void board_late_init(void) {
    late_ready = true;
    arm64_hook(CONFIG_FASTBOOT_GETVAR_ADDRESS, cmd_getvar);
    if (!arm64_patch_call(CONFIG_BOOT_SELECT_CALLER,
                          (uintptr_t)xaga_select_boot_mode))
        printf("kaeru: boot selection hook failed\n");
    if (!arm64_patch_call(CONFIG_AVB_SLOT_VERIFY_CALLER,
                          (uintptr_t)xaga_avb_slot_verify))
        printf("kaeru: AVB initialization hook failed\n");
    /* Suppress the native dm-verity corruption prompt; no logo changes. */
    arm64_force_return(CONFIG_DM_VERITY_WARNING_ADDRESS, 0);
}

static void cmd_xaga_status(const char *arg, void *data, unsigned size) {
    fastboot_info("xaga AArch64 port by kryzen");
    fastboot_info(environment_ready ? "environment hook: ran" : "environment hook: not reached");
    fastboot_info(late_ready ? "late init: ran" : "late init: not reached");
    fastboot_okay("");
}
FASTBOOT_CMD(xaga_status, "oem kaeru-status", cmd_xaga_status, 1);
FASTBOOT_CMD(bldr_spoof, "oem bldr_spoof", cmd_spoof_bootloader_lock, 1);

static void cmd_cancel_recovery(const char *arg, void *data, unsigned size) {
    static uint8_t block[4096] __attribute__((aligned(4096)));
    static uint8_t verify[4096] __attribute__((aligned(4096)));
    if (*skip_spaces(arg)) {
        fastboot_fail("Usage: fastboot oem cancel-recovery");
        return;
    }
    const struct part_info *misc = storage_part_find("misc");
    if (!misc || storage_part_read(misc, block, 0, sizeof(block)) != sizeof(block)) {
        fastboot_fail("Failed to read misc");
        return;
    }
    if (!block[0]) {
        fastboot_info("No recovery request is pending");
        fastboot_okay("");
        return;
    }
    if (memcmp(block, "boot-recovery", sizeof("boot-recovery"))) {
        fastboot_fail("misc contains a different boot command; unchanged");
        return;
    }
    /* Preserve recovery arguments, OTA state, and all other misc bytes. */
    memset(block, 0, 32);
    if (storage_part_write(misc, block, 0, sizeof(block)) != sizeof(block)) {
        fastboot_fail("Failed to write misc; read back before rebooting");
        return;
    }
    if (storage_part_read(misc, verify, 0, sizeof(verify)) != sizeof(verify) ||
        memcmp(block, verify, sizeof(block))) {
        fastboot_fail("misc verification failed; read back before rebooting");
        return;
    }
    fastboot_info("Recovery request cleared; recovery arguments preserved");
    fastboot_okay("");
}
FASTBOOT_CMD(cancel_recovery, "oem cancel-recovery", cmd_cancel_recovery, 1);

bool mem_region_find(const char *name, uintptr_t *base, size_t *size) {
    if (strcmp(name, "lk")) return false;
    *base = CONFIG_BOOTLOADER_BASE;
    *size = CONFIG_BOOTLOADER_SIZE;
    return true;
}
