#!/usr/bin/env python3
import os
import binascii
import sys


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('--push-for-ascii',
                        dest='push_for_ascii',
                        action='store_true',
                        help='Generate push instructions for ASCII string')
    parser.add_argument('--ascii-string',
                        dest='ascii_string',
                        type=str,
                        help='Specify the ASCII string to convert to the HEX format for putting this onto the stack')
    parser.add_argument('--load-library',
                        dest='load_library',
                        action='store_true',
                        help='Generate instructions for loading a DLL')
    parser.add_argument('--load-library-addr',
                        dest='load_library_addr',
                        type=str,
                        help='Specify the absolute address in HEX or a relative offset; '
                             'e.g., --load-library-addr "[ebp+0x14]" or --load-library-addr "0x51233345"')
    parser.add_argument('--load-library-dll-name',
                        dest='load_library_dll_name',
                        type=str,
                        help='Specify the DLL name to load')
    parser.add_argument('--null-free',
                        dest='null_free',
                        action='store_true',
                        help='Avoid NULL bytes in the generated shellcode')
    return parser.parse_args()


def negate_hex(hex_value):
    # Negate the hexadecimal value
    negated_value = hex((0xFFFFFFFF - int(hex_value, 16) + 1) & 0xFFFFFFFF)
    return negated_value


def str_to_hex_little_endian_push(s, null_free=False):
    hex_str = binascii.hexlify(s.encode('utf-8')).decode('utf-8')
    hex_str = ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))
    if len(hex_str) % 8 != 0:
        hex_str = '0' * (8 - len(hex_str) % 8) + hex_str
    result = os.linesep.join([hex_str[i:i + 8] for i in range(0, len(hex_str), 8)])
    result = [f"push 0x{h}" for h in result.split(os.linesep)]

    for h in result:
        if null_free:
            for i in range(5, len(h), 2):
                if h[i:i + 2] == '00':
                    negated_value = negate_hex(h[5:])
                    print(
                        f"mov eax, {negated_value} ;# Move the negated value of the next part of the string \"{s}\" to EAX to avoid NULL bytes\n"
                        f"neg eax ;# Negate EAX to get the original value\n"
                        f"push eax ;# Push EAX onto the stack")
                    break
            else:
                print(f"{h} ;# Push the next part of the string \"{s}\" onto the stack")
        else:
            print(f"{h} ;# Push the next part of the string \"{s}\" onto the stack")


def generate_load_library(dll_name: str, load_library_addr: str, null_free=False):
    print("xor eax, eax ;# NULL EAX")
    str_to_hex_little_endian_push(dll_name, null_free=null_free)
    print("push esp ;# Push ESP to have a pointer to the string that is currently located on the stack")
    print(f"call dword ptr {load_library_addr} ;# Call LoadLibraryA")

def main():
    options = get_arguments()
    if options.push_for_ascii:
        if not options.ascii_string:
            print("Error: --ascii-string is required when --push-for-ascii is given.")
            sys.exit(1)
        str_to_hex_little_endian_push(s=options.ascii_string, null_free=options.null_free)
    elif options.load_library:
        if not options.load_library_dll_name or not options.load_library_addr:
            print("Error: --load-library-dll-name and --load-library-addr are required when --load-library is given.")
            sys.exit(1)
        generate_load_library(dll_name=options.load_library_dll_name, load_library_addr=options.load_library_addr, null_free=options.null_free)
    else:
        print("Error: Either --push-for-ascii or --load-library must be given.")
        sys.exit(1)


if __name__ == "__main__":
    main()
