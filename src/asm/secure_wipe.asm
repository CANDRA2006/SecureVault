section .text
global secure_wipe

secure_wipe:
    mov rcx, rsi
    xor rax, rax
.loop:
    test rcx, rcx
    jz .done
    mov byte [rdi], al
    inc rdi
    dec rcx
    jmp .loop
.done:
    ret