.section .text.startup
.globl _start

_start:
    li $sp, 0x01C00000
    la $t0, __bss_start
    la $t1, __bss_end
clear_bss:
    beq $t0, $t1, done
    sw $zero, 0($t0)
    addiu $t0, $t0, 4
    j clear_bss
    nop
done:
    jal main
    nop
loop:
    j loop
    nop
