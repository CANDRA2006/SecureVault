default rel
section .text
global xor_core

xor_core:
    ; Windows x64 ABI: RCX=data, RDX=key, R8=len
    mov r9, 0
.loop:
    cmp r9, r8
    jge .done
    mov al, [rcx + r9]
    xor al, [rdx + r9]
    mov [rcx + r9], al
    inc r9
    jmp .loop
.done:
    ret