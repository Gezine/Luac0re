ENTRY(_start)

SECTIONS
{
    . = 0x01FF01A0;
    
    .text : { *(.text.startup) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : {
        __bss_start = .;
        *(.bss*) *(COMMON)
        __bss_end = .;
    }
    
    /DISCARD/ : { *(.MIPS.abiflags) *(.reginfo) *(.comment) }
}
