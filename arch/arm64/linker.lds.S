/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(main)
SECTIONS {
    . = 0;
    __image_start = .;
    .text : { KEEP(*(.text.start)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .hash : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }
    . = ALIGN(4096);
    __rx_end = .;
    .fastboot_cmds : {
        __fastboot_cmds_start = .;
        KEEP(*(.fastboot_cmds))
        __fastboot_cmds_end = .;
    }
    .data : { *(.data .data.*) *(.data.rel.ro .data.rel.ro.*) }
    .got : { *(.got .got.*) }
    .rela.dyn : { *(.rela.dyn) }
    __rela_start = ADDR(.rela.dyn);
    __rela_end = ADDR(.rela.dyn) + SIZEOF(.rela.dyn);
    .dynamic : { *(.dynamic) }
    __image_file_end = .;
    .bss (NOLOAD) : {
        . = ALIGN(8);
        __bss_start = .;
        *(.bss .bss.*) *(COMMON)
        __bss_end = .;
    }
    __image_end = .;
    /DISCARD/ : { *(.interp .comment .eh_frame*) }
}
