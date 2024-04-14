#!/usr/bin/env python3
import ctypes
import os
from struct import pack
from termcolor import colored


def run_shellcode_with_virtualalloc(encoding: list, interactive: bool):
    sh = b""
    for e in encoding:
        sh += pack("B", e)
    shellcode = bytearray(sh)
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(shellcode)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(shellcode)))
    print(f"[*] Shellcode located at address {hex(ptr)}")
    if interactive:
        input("[!] Press Enter to execute shellcode")
    print(f"[*] Executing shellcode...")
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


def print_shellcode(encoding: list, var_name: str, interval: int):
    # inserts new lines into the shellcode printed to make it look pretty
    def insert_newlines(string: str, var_name: str, interval: int):
        result = f'{var_name} += b"'
        for i, c in enumerate(string):
            result += c
            if (i + 1) % interval == 0:
                result += f'"{os.linesep}{var_name} += b"'
        result = result + '"'
        return result

    opcodes = ""
    opcodes_len = 0
    for dec in encoding:
        opcodes_len += 1
        opcodes += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    print(f"Assembled shellcode ({opcodes_len} bytes):")
    instructions = ""
    for i, instr in enumerate(opcodes):
        instructions += instr
    if interval:
        formatted_shellcode = f'{var_name} = b""'
        formatted_shellcode += os.linesep
        formatted_shellcode += insert_newlines(instructions, var_name, interval)
    else:
        formatted_shellcode = f'{var_name} = b"{instructions}"'

    # check for bad characters
    if "\\x00" in instructions:
        formatted_shellcode = formatted_shellcode.replace("\\x00", colored("\\x00", 'red'))

    print(formatted_shellcode)
    if "\\x00" in instructions:
        print()
        print(f"[!] Your shellcode seems to contain NULL bytes. You probably have to get rid of them.")
