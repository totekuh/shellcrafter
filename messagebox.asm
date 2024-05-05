global _start
extern _ExitProcess@4
extern _MessageBoxA@16  ; Value after @ is size of args on stack
section .text

; Assembly with NASM for 32-bit
; nasm -f win32 -o messagebox.o messagebox.asm

; Linking for 32-bit explicitly with MinGW 32-bit linker
; i686-w64-mingw32-ld -o messagebox.exe messagebox.o -luser32 -lkernel32

_start:
    ; MessageBoxA( NULL, str_message, "", 0 );
        push 0x0
        push str_empty
        push str_message
        push 0x0
        call _MessageBoxA@16

    ; ExitProcess( 0 );
        push 0x0
        call _ExitProcess@4

section .data

str_message  db  "hack the planet", 0x0
str_empty    db  0x0