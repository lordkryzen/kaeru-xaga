/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
.section .text.start,"ax"
.global main
.type main, %function
main:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x29, sp
    adr x19, main
    adrp x9, __rela_start
    add x9, x9, :lo12:__rela_start
    adrp x10, __rela_end
    add x10, x10, :lo12:__rela_end
1:  cmp x9, x10
    b.hs 2f
    ldp x11, x12, [x9]
    ldr x13, [x9, #16]
    /* Only R_AARCH64_RELATIVE is permitted by the image validator. */
    cmp x12, #1027
    b.ne 5f
    add x11, x19, x11
    add x13, x19, x13
    str x13, [x11]
    add x9, x9, #24
    b 1b
2:  adrp x9, __bss_start
    add x9, x9, :lo12:__bss_start
    adrp x10, __bss_end
    add x10, x10, :lo12:__bss_end
3:  cmp x9, x10
    b.hs 4f
    strb wzr, [x9], #1
    b 3b
4:  adrp x9, kaeru_reloc_delta
    add x9, x9, :lo12:kaeru_reloc_delta
    str x19, [x9]
    bl kaeru_early_init
    b 6f
5:  /* An invalid relocation must not strand the original init caller. */
    ldr x16, 7f
    blr x16
6:  ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.align 3
7:  .quad CONFIG_PLATFORM_INIT_ADDRESS
.align 3
.global xaga_getvar_trampoline
xaga_getvar_trampoline:
    sub sp, sp, #0x60
    stp x29, x30, [sp, #0x40]
    stp x20, x19, [sp, #0x50]
    add x29, sp, #0x40
    ldr x16, 8f
    br x16
8:  .quad CONFIG_FASTBOOT_GETVAR_ADDRESS + 16
.section .note.GNU-stack,"",%progbits
