#!/usr/bin/env python3
import ctypes
import os
import sys
from struct import pack
from termcolor import colored

OUTPUT_FORMAT_PYTHON = 'python'
OUTPUT_FORMAT_C_ARRAY = 'c-array'
OUTPUT_FORMAT_BIN = 'bin'

X86_ARCH = 'x86'
X64_ARCH = 'x64'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def run_shellcode(encoding: list, interactive: bool, arch: str):
    sh = b"".join(pack("B", e) for e in encoding)
    shellcode = bytearray(sh)

    # Setting restype and argtypes for VirtualAlloc and CreateThread
    VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
    VirtualAlloc.restype = ctypes.c_void_p
    VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]

    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
    RtlMoveMemory.restype = None
    RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    # Allocate memory for the shellcode
    ptr = VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    if not ptr:
        raise ValueError("Failed to allocate memory.")

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    RtlMoveMemory(ptr, buf, len(shellcode))

    eprint(f"[*] Shellcode located at address {hex(ptr)}")

    if interactive:
        input("[!] Press Enter to execute shellcode")

    eprint(f"[*] Executing shellcode...")

    # Adjusting for x64 architecture with CreateThread
    if arch == 'x64':
        # Ensure compatibility with x64 by using correct types
        CreateThread = ctypes.windll.kernel32.CreateThread
        CreateThread.restype = ctypes.c_void_p
        CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                 ctypes.c_void_p]

        thread_id = ctypes.c_ulonglong()  # For x64, use c_ulonglong
    else:
        thread_id = ctypes.c_ulong()

    ht = CreateThread(None, 0, ptr, None, 0, ctypes.byref(thread_id))
    if not ht:
        raise ValueError("Failed to create thread.")

    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(ht), -1)


def format_shellcode(shellcode_bytes: bytearray, interval: int):
    # Function to generate opcode string and detect null bytes
    opcodes = "".join(f"\\x{byte:02x}" for byte in shellcode_bytes)
    formatted_opcodes = ""
    null_byte_detected = "\\x00" in opcodes

    if interval > 0:
        # Splitting opcodes with the specified interval
        for i in range(0, len(opcodes), interval):
            end = min(i + interval, len(opcodes))
            formatted_opcodes += opcodes[i:end] + "\n"
    else:
        formatted_opcodes = opcodes

    return formatted_opcodes, null_byte_detected


def print_shellcode(shellcode_assembled: list, var_name: str, interval: int, output_format: str):
    shellcode_bytes = bytearray(shellcode_assembled)
    shellcode_length = len(shellcode_bytes)
    formatted_opcodes, null_byte_detected = format_shellcode(shellcode_bytes, interval * 4)

    if output_format == OUTPUT_FORMAT_PYTHON:
        print_python_shellcode(formatted_opcodes=formatted_opcodes,
                               null_byte_detected=null_byte_detected,
                               var_name=var_name,
                               shellcode_length=shellcode_length)
    elif output_format == OUTPUT_FORMAT_C_ARRAY:
        print_c_array(formatted_opcodes=formatted_opcodes,
                      null_byte_detected=null_byte_detected,
                      var_name=var_name,
                               shellcode_length=shellcode_length, interval=interval)
    elif output_format == OUTPUT_FORMAT_BIN:
        os.write(1, shellcode_bytes)


def print_python_shellcode(formatted_opcodes: str, null_byte_detected: bool, var_name: str, shellcode_length: int):
    # Python shellcode printing logic, now using formatted_opcodes
    shellcode = f'{var_name} = b""\n'
    for line in formatted_opcodes.split("\n"):
        if line:
            shellcode += f'{var_name} += b"{line}"\n'
    shellcode += f"{var_name}_len = {shellcode_length}"

    if null_byte_detected:
        shellcode = shellcode.replace("\\x00", colored("\\x00", 'red'))
        print(shellcode)
        print("\n[!] Your shellcode seems to contain NULL bytes. You probably have to get rid of them.")
    else:
        print(shellcode)

def print_c_array(formatted_opcodes: str, null_byte_detected: bool, var_name: str, shellcode_length: int, interval: int):
    # Ensure each byte is properly formatted as 0xXX
    opcodes = formatted_opcodes.replace("\\x", "0x")

    if null_byte_detected:
        # Highlight potential issues with null bytes
        opcodes = opcodes.replace("0x00", colored("0x00", "red"))

    # Split the opcodes string into individual opcodes
    opcode_list = opcodes.split("0x")[1:]  # Remove the first empty string from split
    opcode_list = [f"0x{opcode}" for opcode in opcode_list if opcode]  # Re-add the 0x prefix

    # Determine the number of opcodes per line
    opcodes_per_line = interval // 4 if interval > 0 else len(opcode_list)

    print(f"unsigned char {var_name}[] = {{")
    print()
    for i in range(0, len(opcode_list), opcodes_per_line):
        # Join a chunk of opcodes for the current line
        line = ', '.join(opcode_list[i:i+opcodes_per_line])
        # Check if this is the last line to avoid adding a comma at the end
        if i + opcodes_per_line < len(opcode_list):
            print(f"  {line.strip()},")
        else:
            print(f"  {line}")
    print("};")
    print(f"unsigned int {var_name}_len = {shellcode_length};")

