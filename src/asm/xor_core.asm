; xor_core.asm — XOR buffer with key (in-place)
;
; Signature (C):
;   void xor_core(uint8_t* data, const uint8_t* key, size_t len)
;
; ABI support:
;   POSIX  x86-64 : data=RDI, key=RSI, len=RDX
;   Windows x64   : data=RCX, key=RDX, len=R8
;
; FIX vs original:
;   1. Added dual ABI support (original only handled Windows x64)
;      On Linux/macOS with POSIX ABI, original code would crash or corrupt.
;   2. QWORD loop processes 8 bytes per iteration (was byte-by-byte = ~8x slower)
;   3. Added zero-length guard

default rel

section .text
global xor_core

xor_core:

%ifdef WINDOWS
    ; Windows x64 ABI: RCX=data, RDX=key, R8=len
    ; Normalize to POSIX convention: RDI=data, RSI=key, RDX=len
    mov     rdi, rcx
    mov     rsi, rdx
    mov     rdx, r8
%endif
    ; POSIX x86-64 ABI: RDI=data, RSI=key, RDX=len (no remapping needed)

    ; --- guard: nothing to do if len == 0 ---
    test    rdx, rdx
    jz      .done

    mov     rcx, rdx        ; rcx = remaining bytes

    ; --- QWORD loop: XOR 8 bytes per iteration ---
    shr     rcx, 3          ; rcx = len / 8
    jz      .byte_tail      ; skip if < 8 bytes

.qword_loop:
    mov     rax, [rdi]      ; load 8 bytes from data
    xor     rax, [rsi]      ; XOR with 8 bytes from key
    mov     [rdi], rax      ; store result
    add     rdi, 8
    add     rsi, 8
    dec     rcx
    jnz     .qword_loop

.byte_tail:
    ; Handle remaining 0-7 bytes
    and     rdx, 7          ; rdx = len % 8
    jz      .done

.byte_loop:
    mov     al, [rdi]
    xor     al, [rsi]
    mov     [rdi], al
    inc     rdi
    inc     rsi
    dec     rdx
    jnz     .byte_loop

.done:
    ret