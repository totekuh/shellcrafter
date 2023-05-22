# Shellcrafter

Shellcrafter is a package containing scripts for developing and generating shellcode.

It provides a collection of utilities for working with shellcode in various ways, such as generating shellcode from assembly instructions, computing hashes from function names, converting ASCII text to hex stack push instructions, loading DLLs, and finding ROP gadgets.

## Installation

To install Shellcrafter, use pip:

```bash
$ pip3 install shellcrafter
```

Or clone this repository and run:

```bash
$ pip3 install .
```


## Usage

Shellcrafter provides the following command-line utilities:

- `keyst-api`: A shellcode generator using the Keystone Engine to assemble assembly instructions into shellcode.
- `shellcode-procedure-generator`: A versatile tool for generating assembly instructions for various purposes. It can generate push instructions for ASCII strings, instructions for loading a DLL, and compute a hash of an input string using an algorithm similar to the one used in assembly for importing a function by its hash. It also provides an option to avoid NULL bytes in the generated shellcode.
- `find-gadgets`: Searches for clean, categorized gadgets from a given list of files.

To get help on how to use each utility, run the corresponding command with the `-h` or `--help` flag:

```bash
$ keyst-api --help
$ shellcode-procedure-generator --help
$ find-gadgets --help
```

## Examples

Here are some examples of how to use the shellcode-procedure-generator tool:

To generate push instructions for an ASCII string:

```bash
$ shellcode-procedure-generator --push-for-ascii --ascii-string shell32.dll
push_str:  ;# push the 'shell32.dll' onto the stack
  push 0x006c6c64 ;# Push the part "lld." of the string "shell32.dll" onto the stack
  push 0x2e32336c ;# Push the part "23ll" of the string "shell32.dll" onto the stack
  push 0x6c656873 ;# Push the part "ehs" of the string "shell32.dll" onto the stack

```

To generate push instructions for an ASCII string and escape the NULL bytes by using the negate approach:

```bash
$ shellcode-procedure-generator --push-for-ascii --ascii-string shell32.dll --null-free
push_str:  ;# push the 'shell32.dll' onto the stack
  mov eax, 0xff93939c ;# Move the negated value of the part "lld." of the string "shell32.dll" to EAX to avoid NULL bytes
  neg eax ;# Negate EAX to get the original value
  push eax ;# Push EAX onto the stack
  push 0x2e32336c ;# Push the part "23ll" of the string "shell32.dll" onto the stack
  push 0x6c656873 ;# Push the part "ehs" of the string "shell32.dll" onto the stack

```

To generate instructions for loading a DLL:

```bash
$ shellcode-procedure-generator --load-library --load-library-addr "[ebp+0x10]" --load-library-dll-name shell32.dll
load_lib:  ;# load the shell32.dll DLL
  xor eax, eax ;# NULL EAX
  push 0x006c6c64 ;# Push the part "lld." of the string "shell32.dll" onto the stack
  push 0x2e32336c ;# Push the part "23ll" of the string "shell32.dll" onto the stack
  push 0x6c656873 ;# Push the part "ehs" of the string "shell32.dll" onto the stack
  push esp ;# Push ESP to have a pointer to the string that is currently located on the stack
  call dword ptr [ebp+0x10] ;# Call LoadLibraryA

```

To do the same, but escape the NULL byte:

```bash
$ shellcode-procedure-generator --load-library --load-library-addr "[ebp+0x10]" --load-library-dll-name shell32.dll --null-free
load_lib:  ;# load the shell32.dll DLL
  xor eax, eax ;# NULL EAX
  mov eax, 0xff93939c ;# Move the negated value of the part "lld." of the string "shell32.dll" to EAX to avoid NULL bytes
  neg eax ;# Negate EAX to get the original value
  push eax ;# Push EAX onto the stack
  push 0x2e32336c ;# Push the part "23ll" of the string "shell32.dll" onto the stack
  push 0x6c656873 ;# Push the part "ehs" of the string "shell32.dll" onto the stack
  push esp ;# Push ESP to have a pointer to the string that is currently located on the stack
  call dword ptr [ebp+0x10] ;# Call LoadLibraryA
```

Calculate a hash of the given input string:

```bash
$ shellcode-procedure-generator --hash LoadLibraryA
Hash: 0xec0e4e8e
```

Print out the hashing algorithm used to generate the hash value:

```bash
$ shellcode-procedure-generator --hash-alg                                                                                     

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
```