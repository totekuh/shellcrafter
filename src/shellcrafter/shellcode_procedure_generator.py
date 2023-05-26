#!/usr/bin/env python3
import os
import binascii
import pprint

import sys

module_path = os.path.dirname(__file__)
sys.path.append(module_path)
import numpy

from argparse import ArgumentParser


def get_arguments():
    parser = ArgumentParser(description="Generate assembly instructions for various purposes")

    commands = parser.add_argument_group('commands')
    commands.add_argument('--push-for-ascii',
                          dest='push_for_ascii',
                          action='store_true',
                          help='Generate push instructions for ASCII string')
    commands.add_argument('--load-library',
                          dest='load_library',
                          action='store_true',
                          help='Generate instructions for loading a DLL')
    commands.add_argument('--null-free',
                          dest='null_free',
                          action='store_true',
                          help='Avoid NULL bytes in the generated shellcode')
    commands.add_argument('--hash',
                          dest='hash',
                          type=str,
                          help='Compute a hash of the input string. '
                               'Use --hash-alg argument to see the corresponding algorithm on assembly.')
    commands.add_argument('--hash-alg',
                          dest='hash_alg',
                          action='store_true',
                          help='Print out the hashing algorithm used to hash the value passed with the --hash flag.')
    commands.add_argument('--write',
                          dest='write',
                          action='store_true',
                          help='Generate instructions for writing an ASCII string to memory')
    commands.add_argument("--print-data-types",
                          dest="print_data_types",
                          action="store_true",
                          help="Print out information about commonly used Win32 data types")

    arguments = parser.add_argument_group('arguments')
    arguments.add_argument('--ascii-string',
                           dest='ascii_string',
                           type=str,
                           help='Specify the ASCII string to convert to the HEX format '
                                'for putting this onto the stack with `--push-for-ascii` command '
                                'or to write to memory with `--write` command')
    arguments.add_argument('--load-library-addr',
                           dest='load_library_addr',
                           type=str,
                           help='Specify the absolute address in HEX or a relative offset; '
                                'e.g., --load-library-addr "[ebp+0x14]" or --load-library-addr "0x51233345"')
    arguments.add_argument('--load-library-dll-name',
                           dest='load_library_dll_name',
                           type=str,
                           help='Specify the DLL name to load')
    arguments.add_argument('--write-addr',
                           dest='write_addr',
                           type=str,
                           help='Specify the address to write to in HEX or a relative offset; '
                                'e.g., --write-addr "[ebp-0x50]" or --write-addr "0x51233345"')

    return parser.parse_args()

# Define data types
data_types = {
    "LPCSTR": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Long Pointer to a Constant String. Used for C-style null-terminated strings."
    },
    "LPVOID": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Long Pointer to Void. Can point to any type of data."
    },
    "LPBOOL": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Long Pointer to BOOL. Used for passing boolean values by reference."
    },
    "DWORD": {
        "type": "integer",
        "size": 4,  # 32-bit integer size
        "description": "Double Word. A 32-bit unsigned integer."
    },
    "LPPROGRESS_ROUTINE": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Long Pointer to PROGRESS_ROUTINE. Used for callback functions."
    },
    "BOOL": {
        "type": "integer",
        "size": 4,  # 32-bit integer size
        "description": "Boolean. Used for true/false values."
    },
    "BYTE": {
        "type": "integer",
        "size": 1,  # 8-bit integer size
        "description": "Byte. An 8-bit unsigned integer."
    },
    "WORD": {
        "type": "integer",
        "size": 2,  # 16-bit integer size
        "description": "Word. A 16-bit unsigned integer."
    },
    "LONG": {
        "type": "integer",
        "size": 4,  # 32-bit integer size
        "description": "Long. A 32-bit signed integer."
    },
    "WCHAR": {
        "type": "integer",
        "size": 2,  # 16-bit integer size
        "description": "Wide Character. Used for Unicode characters."
    },
    "LPWSTR": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Long Pointer to a Wide String. Used for Unicode C-style null-terminated strings."
    },
    "HANDLE": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle. Used as a reference to a system resource."
    },
    "HWND": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to a Window. Used as a reference to a window object."
    },
    "HINSTANCE": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to an Instance. Used as a reference to an application instance."
    },
    "UINT": {
        "type": "integer",
        "size": 4,  # 32-bit integer size
        "description": "Unsigned Integer. A 32-bit unsigned integer."
    },
    "SHORT": {
        "type": "integer",
        "size": 2,  # 16-bit integer size
        "description": "Short. A 16-bit signed integer."
    },
    "FLOAT": {
        "type": "float",
        "size": 4,  # 32-bit float size
        "description": "Float. A 32-bit floating point number."
    },
    "DOUBLE": {
        "type": "float",
        "size": 8,  # 64-bit double size
        "description": "Double. A 64-bit floating point number."
    },
    "LPDWORD": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Long Pointer to DWORD. Used for passing DWORD values by reference."
    },
    "LPLONG": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Long Pointer to LONG. Used for passing LONG values by reference."
    },
    "HDC": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to a Device Context. Used as a reference to a device context."
    },
    "HBITMAP": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to a Bitmap. Used as a reference to a bitmap object."
    },
    "HBRUSH": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to a Brush. Used as a reference to a brush object."
    },
    "HCURSOR": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to a Cursor. Used as a reference to a cursor object."
    },
    "HICON": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to an Icon. Used as a reference to an icon object."
    },
    "HMENU": {
        "type": "pointer",
        "size": 4,  # 32-bit pointer size
        "description": "Handle to a Menu. Used as a reference to a menu object."
    }
}

def print_hash_alg():
    print("""
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

compute_hash_finished:""")


def ror_str(byte, count):
    """
    Rotate the given byte right by the specified count.
    """
    binb = numpy.base_repr(byte, 2).zfill(32)
    for _ in range(count):
        binb = binb[-1] + binb[0:-1]
    return int(binb, 2)


def compute_hash(function_name):
    edx = 0x00
    ror_count = 0
    for eax in function_name:
        edx = edx + ord(eax)
        if ror_count < len(function_name) - 1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    print(f"Hash: {hex(edx)}")


def negate_hex(hex_value):
    # Negate the hexadecimal value
    negated_value = hex((0xFFFFFFFF - int(hex_value, 16) + 1) & 0xFFFFFFFF)
    return negated_value


def str_to_hex_little_endian_push(s, null_free=False):
    hex_str = binascii.hexlify(s.encode('utf-8')).decode('utf-8')
    hex_str = ''.join(reversed([hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]))
    if len(hex_str) % 8 != 0:
        hex_str = '0' * (8 - len(hex_str) % 8) + hex_str
    result = os.linesep.join([hex_str[i:i + 8] for i in range(0, len(hex_str), 8)])
    result = [f"push 0x{h}" for h in result.split(os.linesep)]

    for index, h in enumerate(result):
        part = s[::-1][index * 4: index * 4 + 4]
        if null_free:
            for i in range(5, len(h), 2):
                if h[i:i + 2] == '00':
                    negated_value = negate_hex(h[5:])
                    print(
                        f"  mov eax, {negated_value} ;# Move the negated value of the part \"{part}\" of the string \"{s}\" to EAX to avoid NULL bytes")
                    print("  neg eax ;# Negate EAX to get the original value")
                    print("  push eax ;# Push EAX onto the stack")
                    break
            else:
                print(f"  {h} ;# Push the part \"{part}\" of the string \"{s}\" onto the stack")
        else:
            print(f"  {h} ;# Push the part \"{part}\" of the string \"{s}\" onto the stack")


def generate_load_library(dll_name: str, load_library_func_addr: str, null_free=False):
    print(f"load_lib:  ;# load the {dll_name} DLL")
    print("  xor eax, eax ;# NULL EAX")
    print("  push eax ;# Push NULL terminator for the string")
    str_to_hex_little_endian_push(dll_name, null_free=null_free)
    print("  push esp ;# Push ESP to have a pointer to the string that is currently located on the stack")
    print(f"  call dword ptr {load_library_func_addr} ;# Call LoadLibraryA")


def write_to_memory(s: str, write_addr: str, null_free=False):
    hex_str = binascii.hexlify(s.encode('utf-8')).decode('utf-8')
    hex_str = ''.join(reversed([hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]))
    if len(hex_str) % 8 != 0:
        hex_str = '0' * (8 - len(hex_str) % 8) + hex_str
    result = os.linesep.join([hex_str[i:i + 8] for i in range(0, len(hex_str), 8)])
    result = [f"mov ecx, 0x{h}" for h in result.split(os.linesep)]
    result.reverse()  # Reverse the order of the instructions

    print(f"write_str: ;# write {s} to {write_addr}")
    print(f"  xor eax, eax  ;# NULL EAX")
    print(f"  xor ecx, ecx  ;# NULL ECX")
    print(f"  lea eax, {write_addr} ;# Load the address to write to into EAX")
    for index, h in enumerate(result):
        part = s[index * 4: index * 4 + 4]
        if null_free:
            hex_value = h.split(", ")[1]  # Extract the hexadecimal value from the instruction string
            for i in range(2, len(hex_value), 2):
                if hex_value[i:i + 2] == '00':
                    negated_value = negate_hex(
                        hex_value[2:])  # Pass only the hexadecimal value to the negate_hex function
                    print(
                        f"  mov ecx, {negated_value} ;# Move the negated value of the part \"{part}\" of the string \"{s}\" to ECX to avoid NULL bytes")
                    print("  neg ecx ;# Negate ECX to get the original value")
                    break
            else:
                print(f"  {h} ;# Move the part \"{part}\" of the string \"{s}\" to ECX")
        else:
            print(f"  {h} ;# Move the part \"{part}\" of the string \"{s}\" to ECX")
        write_offset = f"eax+0x{index * 4:02x}"
        if write_offset == 'eax+0x00':
            write_offset = 'eax'
        print(f"  mov [{write_offset}], ecx ;# Write the part \"{part}\" of the string \"{s}\" to memory")


def main():
    options = get_arguments()
    if options.hash_alg:
        print_hash_alg()
    elif options.print_data_types:
        pprint.pprint(data_types, indent=4)
    elif options.hash:
        compute_hash(options.hash)
    elif options.push_for_ascii:
        if not options.ascii_string:
            print("Error: --ascii-string is required when --push-for-ascii is given.")
            sys.exit(1)
        print(f"push_str:  ;# push the '{options.ascii_string}' onto the stack")
        str_to_hex_little_endian_push(s=options.ascii_string, null_free=options.null_free)
    elif options.load_library:
        if not options.load_library_dll_name or not options.load_library_addr:
            print("Error: --load-library-dll-name and --load-library-addr are required when --load-library is given.")
            sys.exit(1)
        generate_load_library(dll_name=options.load_library_dll_name, load_library_func_addr=options.load_library_addr,
                              null_free=options.null_free)
    elif options.write:
        if not options.ascii_string or not options.write_addr:
            print("Error: --ascii-string and --write-addr are required when --write is given.")
            sys.exit(1)
        write_to_memory(s=options.ascii_string, write_addr=options.write_addr, null_free=options.null_free)
    else:
        print("Error: Either --push-for-ascii, --write or --load-library must be given.")
        sys.exit(1)


if __name__ == "__main__":
    main()
