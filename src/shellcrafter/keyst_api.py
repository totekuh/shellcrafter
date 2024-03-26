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


def run_shellcode(encoding: list, interactive: bool):
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
    eprint(f"[*] Shellcode located at address {hex(ptr)}")
    if interactive:
        input("[!] Press Enter to execute shellcode")
    eprint(f"[*] Executing shellcode...")
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


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
        opcodes = opcodes.replace("0x00", "0x00 /* null byte */")

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

    # initialize the keystone engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    try:
        shellcode_assembled, count = ks.asm(options.instructions)
    except KsError as ks_error:
        eprint(f"Shellcode compilation failed: {ks_error}")
        exit(1)
    eprint(f"[+] {count} instructions have been encoded")

    if options.run:
        run_shellcode(encoding=shellcode_assembled,
                      interactive=options.interactive)
    else:
        print_shellcode(shellcode_assembled=shellcode_assembled, var_name=options.var_name, interval=options.interval,
                        output_format=options.output_format)


if __name__ == "__main__":
    main()
