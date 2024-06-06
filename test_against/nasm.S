[bits 64]
section .text
global _start
_start:
    call library_function
    add eax, '0'
    mov [buffer], eax
    mov eax, 1 ; write
    mov edi, 1 ; stdout
    mov rsi, buffer
    mov edx, 1
    syscall
    mov eax, 231 ; exit(0);
    xor edi, edi
    syscall
library_function:
    mov eax, 5
    ret

section .data
buffer:
    db 0
