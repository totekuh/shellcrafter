#!/usr/bin/env python3
import ctypes
import os
from struct import pack
from termcolor import colored

from keystone import *

DEFAULT_VAR_NAME = "shellcode"


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
                        default=48,
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


def main():
    options = get_arguments()

    # initialize the keystone engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    try:
        encoding, count = ks.asm(options.instructions)
    except KsError as ks_error:
        print(f"Shellcode compilation failed: {ks_error}")
        exit(1)
    print(f"[+] {count} instructions have been encoded")

    if options.run:
        run_shellcode(encoding=encoding,
                      interactive=options.interactive)
    else:
        print_shellcode(encoding=encoding,
                        var_name=options.var_name,
                        interval=options.interval)


if __name__ == "__main__":
    main()
