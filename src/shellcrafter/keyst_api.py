#!/usr/bin/env python3
import ctypes
import os
from struct import pack
from termcolor import colored
import sys

from keystone import *

DEFAULT_VAR_NAME = "shellcode"

OUTPUT_FORMAT_PYTHON = 'python'
OUTPUT_FORMAT_C_ARRAY = 'c-array'
OUTPUT_FORMAT_BIN = 'bin'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Keystone Shellcode Generator")
    parser.add_argument("-i",
                        "--instructions",
                        dest="instructions",
                        required=False,
                        type=str,
                        help="Specify a set of assembly instructions to generate the shellcode")
    parser.add_argument('-if',
                        '--instructions-file',
                        dest='instructions_file',
                        required=False,
                        type=str,
                        help="Specify a file with assembly instructions to generate the shellcode")
    parser.add_argument('-r',
                        '--run',
                        dest='run',
                        required=False,
                        action='store_true',
                        help="Provide this flag to run your shellcode using the keystone engine on a Windows machine "
                             "in the context of the python3.exe process. "
                             "Without providing this flag the script just prints out the assembled shellcode.")
    parser.add_argument('-vn',
                        '--var-name',
                        dest='var_name',
                        required=False,
                        default=DEFAULT_VAR_NAME,
                        type=str,
                        help="Specify the variable name for your shellcode to be printed with, "
                             "so that you can easily copypaste it into your exploit. "
                             f"Default is '{DEFAULT_VAR_NAME}'.")
    parser.add_argument('--interval',
                        dest='interval',
                        required=False,
                        default=24,
                        choices=[0, 12, 24, 48, 96, 192],
                        type=int,
                        help="Specify the number of opcodes per line while printing the shellcode. "
                             f"Default is {48}. "
                             f"0 indicates that the shellcode should be printed as a single line.")
    parser.add_argument('--interactive',
                        dest='interactive',
                        required=False,
                        action='store_true',
                        help='Specify if the script execute the shellcode after creating a virtual thread, '
                             'or if the script should wait until the user attaches a debugger to the process. '
                             "By default the script doesn't wait for the user to hit any key "
                             "before executing the shellcode. ")
    parser.add_argument('--output-format',
                        dest='output_format',
                        required=False,
                        default=OUTPUT_FORMAT_PYTHON,
                        choices=[OUTPUT_FORMAT_PYTHON, OUTPUT_FORMAT_C_ARRAY, OUTPUT_FORMAT_BIN],
                        help="Specify the output format of the shellcode: 'python', 'c-array', or 'bin'. Default is 'python'.")
    # Add argument for architecture
    parser.add_argument('--arch',
                        dest='arch',
                        required=False,
                        default='x86',
                        choices=['x86', 'x64'],
                        help="Specify the architecture ('x86' or 'x64'). Default is 'x86'.")

    options = parser.parse_args()
    if options.instructions and options.instructions_file:
        parser.error('Either the --instructions-file (-ir) or --instructions (-i) argument must be given')
    if not options.instructions and not options.instructions_file:
        parser.error('Either the --instructions-file (-ir) or --instructions (-i) argument must be given')

    if options.instructions_file:
        instructions_file = options.instructions_file
        if os.path.exists(instructions_file):
            with open(instructions_file, 'r', encoding='utf-8', errors='ignore') as f:
                options.instructions = f.read()
        else:
            parser.error(f"The given file {instructions_file} doesn't exist")
    return options


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

    # Allocate memory for shellcode
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



def main():
    options = get_arguments()

    # Determine the architecture and mode for the Keystone engine
    if options.arch == 'x86':
        arch = KS_ARCH_X86
        mode = KS_MODE_32
    elif options.arch == 'x64':
        arch = KS_ARCH_X86
        mode = KS_MODE_64
    else:
        eprint(f"Unsupported architecture: {options.arch}")
        sys.exit(1)

    # Initialize the keystone engine with the specified architecture and mode
    ks = Ks(arch, mode)

    try:
        shellcode_assembled, count = ks.asm(options.instructions)
    except KsError as ks_error:
        eprint(f"Shellcode compilation failed: {ks_error}")
        exit(1)
    eprint(f"[+] {count} instructions have been encoded")

    if options.run:
        run_shellcode(encoding=shellcode_assembled,
                      interactive=options.interactive,
                      arch=options.arch)
    else:
        print_shellcode(shellcode_assembled=shellcode_assembled, var_name=options.var_name, interval=options.interval,
                        output_format=options.output_format)


if __name__ == "__main__":
    main()
