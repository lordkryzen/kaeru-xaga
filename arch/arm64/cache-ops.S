/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
.text
.align 2
.global arch_clean_cache_range
.type arch_clean_cache_range, %function
arch_clean_cache_range:
    cbz x1, 2f
    add x2, x0, x1
    mrs x3, ctr_el0
    ubfx x3, x3, #16, #4
    mov x4, #4
    lsl x3, x4, x3
    sub x4, x3, #1
    bic x0, x0, x4
1:  dc cvac, x0
    add x0, x0, x3
    cmp x0, x2
    b.lo 1b
2:  dsb sy
    ret

.global arch_clean_invalidate_cache_range
.type arch_clean_invalidate_cache_range, %function
arch_clean_invalidate_cache_range:
    cbz x1, 2f
    add x2, x0, x1
    mrs x3, ctr_el0
    ubfx x3, x3, #16, #4
    mov x4, #4
    lsl x3, x4, x3
    sub x4, x3, #1
    bic x0, x0, x4
1:  dc civac, x0
    add x0, x0, x3
    cmp x0, x2
    b.lo 1b
2:  dsb sy
    ret

.global arch_sync_cache_range
.type arch_sync_cache_range, %function
arch_sync_cache_range:
    cbz w1, 3f
    mov x5, x0
    add x2, x0, w1, uxtw
    mrs x3, ctr_el0
    ubfx x4, x3, #16, #4
    mov x6, #4
    lsl x4, x6, x4
    sub x7, x4, #1
    bic x0, x0, x7
1:  dc cvau, x0
    add x0, x0, x4
    cmp x0, x2
    b.lo 1b
    dsb ish
    and x3, x3, #0xf
    lsl x3, x6, x3
    sub x7, x3, #1
    bic x0, x5, x7
2:  ic ivau, x0
    add x0, x0, x3
    cmp x0, x2
    b.lo 2b
3:  dsb ish
    isb
    ret

.global enable_unaligned
.type enable_unaligned, %function
enable_unaligned:
    mrs x0, sctlr_el1
    bic x1, x0, #2
    msr sctlr_el1, x1
    isb
    ret
.global restore_unaligned
.type restore_unaligned, %function
restore_unaligned:
    msr sctlr_el1, x0
    isb
    ret
.section .note.GNU-stack,"",%progbits
