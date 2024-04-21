# Shellcrafter

Shellcrafter is a comprehensive toolkit designed for shellcode development and gadget finding. It integrates several utilities to assist in the generation of shellcode from assembly instructions, conversion of ASCII text to hexadecimal stack push instructions, loading of DLLs, finding ROP gadgets, and more.

## Installation

To install Shellcrafter, you can either install it directly using pip if it's available in the Python Package Index or by cloning the repository and installing it locally:

```bash
$ pip3 install shellcrafter
```

Or clone the repository and install using:

```bash
$ git clone https://github.com/totekuh/shellcrafter.git
$ cd shellcrafter
$ pip3 install .
```

## Usage

Shellcrafter is structured around multiple command-line utilities grouped under a Typer application. 

Here's how to use the various utilities:

### Keystone API - Shellcode Compiler

Compile shellcode from assembly instructions:

```bash
$ shellcrafter shellcode compile --instructions "mov ax, 1"
[+] 1 instructions have been encoded
shellcode = b""
shellcode += b"\x66\xb8\x01\x00"
shellcode_len = 4
```

Also for x64:

```bash
$ shellcrafter shellcode compile --instructions "mov ax, 1" --arch x64
```

Supports compiling shellcode from a file:

```bash
$ cat hash.asm

compute_hash:
  xor eax, eax                 ;# NULL EAX
  cdq                          ;# NULL EDX
  cld                          ;# clear direction (clears the direction flag DF in the EFLAGS register)

compute_hash_again:
  lodsb                        ;# load the next byte from ESI into AL
  test al, al                  ;# check if AL contains the NULL terminator
  jz compute_hash_finished     ;# if the ZF is set, we've hit the NULL terminator
  ror edx, 0x0d                ;# rotate EDX 13 bits to the right
  add edx, eax                 ;# add the new hashed byte to the accumulator
  jmp compute_hash_again       ;# next iteration

compute_hash_finished:
$ shellcrafter shellcode compile -if hash.asm 
[+] 24 instructions have been encoded
shellcode = b""
shellcode += b"\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4"
shellcode_len = 16
```

For more help:

```bash
shellcrafter shellcode compile --help
```

### Shellcode Generator

This tool can generate various types of shellcode operations:

#### Generate Stack Push Instructions for an ASCII String

Generate instructions for pushing the `example.dll` string on the stack:
```bash
shellcrafter codegen push-ascii --ascii-string "example.dll"
push_str:  ;# push the 'example.dll' onto the stack
  push 0x006c6c64 ;# Push the part "lld." of the string "example.dll" onto the stack
  push 0x2e656c70 ;# Push the part "elpm" of the string "example.dll" onto the stack
  push 0x6d617865 ;# Push the part "axe" of the string "example.dll" onto the stack
```

Use the negate operation to avoid NULL byte if necessary:

```bash
shellcrafter codegen push-ascii --ascii-string "example.dll" --null-free
push_str:  ;# push the 'example.dll' onto the stack
  mov eax, 0xff93939c ;# Move the negated value of the part "lld." of the string "example.dll" to EAX to avoid NULL bytes
  neg eax ;# Negate EAX to get the original value
  push eax ;# Push EAX onto the stack
  push 0x2e656c70 ;# Push the part "elpm" of the string "example.dll" onto the stack
  push 0x6d617865 ;# Push the part "axe" of the string "example.dll" onto the stack
```

#### Load a DLL

Generate code for loading a DLL into the target process. 
The DLL's name and the address of the LoadLibraryA function have to be provided.
```bash
shellcrafter codegen load-library --dll-name "example.dll" --load-library-addr "[ebp-0x04]"
load_lib:  ;# load the example.dll DLL
  xor eax, eax ;# NULL EAX
  push eax ;# Push NULL terminator for the string
  push 0x006c6c64 ;# Push the part "lld." of the string "example.dll" onto the stack
  push 0x2e656c70 ;# Push the part "elpm" of the string "example.dll" onto the stack
  push 0x6d617865 ;# Push the part "axe" of the string "example.dll" onto the stack
  push esp ;# Push ESP to have a pointer to the string that is currently located on the stack
  call dword ptr [ebp-0x04] ;# Call LoadLibraryA
```

#### Write ASCII String to Memory

Generate code for writing an ASCII string to the given memory address:

```bash
$ shellcrafter codegen write --ascii-string "http://example.com" --write-addr "[eax]"
write_str: ;# write http://example.com to [eax]
  xor eax, eax  ;# NULL EAX
  xor ecx, ecx  ;# NULL ECX
  lea eax, [eax] ;# Load the address to write to into EAX
  mov ecx, 0x70747468 ;# Move the part "http" of the string "http://example.com" to ECX
  mov [eax], ecx ;# Write the part "http" of the string "http://example.com" to memory
  mov ecx, 0x652f2f3a ;# Move the part "://e" of the string "http://example.com" to ECX
  mov [eax+0x04], ecx ;# Write the part "://e" of the string "http://example.com" to memory
  mov ecx, 0x706d6178 ;# Move the part "xamp" of the string "http://example.com" to ECX
  mov [eax+0x08], ecx ;# Write the part "xamp" of the string "http://example.com" to memory
  mov ecx, 0x632e656c ;# Move the part "le.c" of the string "http://example.com" to ECX
  mov [eax+0x0c], ecx ;# Write the part "le.c" of the string "http://example.com" to memory
  mov ecx, 0x00006d6f ;# Move the part "om" of the string "http://example.com" to ECX
  mov [eax+0x10], ecx ;# Write the part "om" of the string "http://example.com" to memory
```

### Gadget Finder

Search for gadgets in binary files:

```bash
$ shellcrafter gadgets find-gadgets "wsock32.dll"
```

### Compute Hash of a Function Name

Get ROR13 hash of the given string:

```bash
$ shellcrafter codegen hash "CreateProcess"
Hash: 0x7fc622d6
```
