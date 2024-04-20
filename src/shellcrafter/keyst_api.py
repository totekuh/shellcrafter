#!/usr/bin/env python3
import ctypes
import errno
import os
import sys
from struct import pack

from keystone import *
from termcolor import colored
from typer import echo, Exit

OUTPUT_FORMAT_PYTHON = 'python'
OUTPUT_FORMAT_C_ARRAY = 'c-array'
OUTPUT_FORMAT_BIN = 'bin'

X86_ARCH = 'x86'
X64_ARCH = 'x64'


def read_instructions_from_file(filepath: str) -> str:
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    else:
        print(f"The given file {filepath} doesn't exist")
        raise Exit(code=1)


def get_instructions(instructions: str, instructions_file: str):
    """ Retrieves assembly instructions from a file or direct input. """
    if instructions and instructions_file:
        echo("Either the --instructions-file or --instructions option must be given, not both.", err=True)
        raise Exit(code=1)
    if not instructions and not instructions_file:
        echo("Either the --instructions-file or --instructions option must be given.", err=True)
        raise Exit(code=1)

    if instructions_file:
        if not os.path.exists(instructions_file):
            echo("The given instructions file doesn't exist.", err=True)
            raise Exit(code=1)
        # Read the file content to check if it's empty.
        with open(instructions_file, 'r', encoding='utf-8') as file:
            contents = file.read()
            if not contents:
                echo("The file --instructions-file seems to be empty.", err=True)
                raise Exit(code=1)
        return read_instructions_from_file(instructions_file)
    return instructions


def assemble_instructions(instructions: str, arch: str):
    """ Assemble instructions based on architecture. """
    if arch == X86_ARCH:
        ks_arch = KS_ARCH_X86
        ks_mode = KS_MODE_32
    elif arch == X64_ARCH:
        ks_arch = KS_ARCH_X86
        ks_mode = KS_MODE_64
    else:
        eprint(f"Unsupported architecture: {arch}")
        sys.exit(1)

    ks = Ks(ks_arch, ks_mode)
    try:
        return ks.asm(instructions)
    except KsError as ks_error:
        if "INVALIDOPERAND" in str(ks_error):
            eprint(f"Invalid operand error. Wrong architecture?")
            raise Exit(code=1)
        else:
            eprint(f"Shellcode compilation failed: {ks_error}")
            raise Exit(code=1)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def run_shellcode(encoding, interactive, arch, platform):
    print(f"[*] Detected platform: {platform}")

    if platform == 'windows':
        run_shellcode_on_windows(arch, encoding, interactive)
    elif platform == 'linux':
        run_shellcode_on_linux(interactive, shellcode=bytearray(encoding))
    else:
        raise ValueError("Unsupported platform or architecture.")
    print("[+] Shellcode execution finished")


def run_shellcode_on_linux(interactive, shellcode):
    libc = ctypes.CDLL("libc.so.6")
    libpthread = ctypes.CDLL("libpthread.so.0")

    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t]

    page_size = libc.getpagesize()
    PROT_READ_WRITE_EXEC = 0x7
    MAP_PRIVATE_ANON = 0x22

    ptr = libc.mmap(None, page_size, PROT_READ_WRITE_EXEC, MAP_PRIVATE_ANON, -1, 0)
    if ptr == ctypes.c_void_p(-1).value:
        raise Exception(f"Memory allocation failed with error: {errno.errorcode[ctypes.get_errno()]}")

    shellcode_bytes = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
    ctypes.memmove(ptr, shellcode_bytes, len(shellcode))

    if interactive:
        input("[!] Press Enter to execute shellcode")

    print("[*] Executing shellcode...")

    FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int64)  # Define function type that returns an int64
    shellcode_func = FUNC_TYPE(ptr)

    thread = ctypes.c_void_p()
    retval = ctypes.c_int64()  # This will hold the return value from the shellcode

    err = libpthread.pthread_create(ctypes.byref(thread), None, shellcode_func, None)
    if err != 0:
        raise Exception(f"Error creating thread with error code: {errno.errorcode[err]}")

    if libpthread.pthread_join(thread, ctypes.byref(retval)) != 0:
        raise Exception("Error joining thread")

    print(f"Shellcode returned: {retval.value}")


def run_shellcode_on_windows(arch, encoding, interactive):
    sh = b"".join(pack("B", e) for e in encoding)
    shellcode = bytearray(sh)

    VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
    VirtualAlloc.restype = ctypes.c_void_p
    VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]

    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
    RtlMoveMemory.restype = None
    RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    ptr = VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
    if not ptr:
        raise ValueError("Failed to allocate memory.")

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    RtlMoveMemory(ptr, buf, len(shellcode))
    eprint(f"[*] Shellcode located at address {hex(ptr)}")

    if interactive:
        input("[!] Press Enter to execute shellcode")

    eprint(f"[*] Executing shellcode...")

    CreateThread = ctypes.windll.kernel32.CreateThread
    CreateThread.restype = ctypes.c_void_p
    CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                             ctypes.c_void_p]

    if arch == 'x64':
        thread_id = ctypes.c_ulonglong()
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


def print_c_array(formatted_opcodes: str, null_byte_detected: bool, var_name: str, shellcode_length: int,
                  interval: int):
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
        line = ', '.join(opcode_list[i:i + opcodes_per_line])
        # Check if this is the last line to avoid adding a comma at the end
        if i + opcodes_per_line < len(opcode_list):
            print(f"  {line.strip()},")
        else:
            print(f"  {line}")
    print("};")
    print(f"unsigned int {var_name}_len = {shellcode_length};")
