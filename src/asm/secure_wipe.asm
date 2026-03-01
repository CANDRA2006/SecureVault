; secure_wipe.asm — Cryptographic memory zeroization
;
; Signature (C):
;   void secure_wipe(uint8_t* data, size_t size)
;
; ABI support:
;   POSIX  x86-64 : data=RDI, size=RSI
;   Windows x64   : data=RCX, size=RDX
;
; Strategy:
;   1. Normalize args to RDI/RSI (POSIX convention internally)
;   2. Zero 8 bytes at a time (QWORD) while len >= 8
;   3. Zero remaining 1-7 bytes one byte at a time
;   4. SFENCE to prevent store-reordering past this point

default rel

section .text
global secure_wipe

secure_wipe:

%ifdef WINDOWS
    ; Windows x64 ABI: RCX=data, RDX=size
    ; Remap to POSIX registers for unified body
    mov     rdi, rcx
    mov     rsi, rdx
%endif
    ; POSIX x86-64 ABI: RDI=data, RSI=size

    ; --- guard: nothing to do if size == 0 ---
    test    rsi, rsi
    jz      .done

    xor     eax, eax            ; zero value (clears upper 32 bits of RAX too)
    mov     rcx, rsi            ; rcx = remaining bytes

    ; --- QWORD loop: zero 8 bytes per iteration ---
    shr     rcx, 3              ; rcx = size / 8
    jz      .byte_loop_setup    ; skip if < 8 bytes total

.qword_loop:
    mov     qword [rdi], rax    ; store 8 zero bytes
    add     rdi, 8
    dec     rcx
    jnz     .qword_loop

.byte_loop_setup:
    ; Handle remaining 0-7 bytes
    and     rsi, 7              ; rsi = size % 8
    jz      .fence

.byte_loop:
    mov     byte [rdi], al      ; store 1 zero byte
    inc     rdi
    dec     rsi
    jnz     .byte_loop

.fence:
    ; Store fence: ensures all zero-stores are globally visible
    ; before any subsequent memory operations.
    sfence

.done:
    ret