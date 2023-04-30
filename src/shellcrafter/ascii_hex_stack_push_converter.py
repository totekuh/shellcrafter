#!/usr/bin/env python3
import os
import textwrap
import binascii


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-i',
                        '--input',
                        dest='input',
                        required=True,
                        type=str,
                        help='Specify the ASCII string to convert to the HEX format for putting this onto the stack')
    return parser.parse_args()


def str_to_hex_little_endian_push(s):
    hex_str = binascii.hexlify(s.encode('utf-8')).decode('utf-8')
    hex_str = ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))
    if len(hex_str) % 8 != 0:
        hex_str = '0' * (8 - len(hex_str) % 8) + hex_str
    result = os.linesep.join([hex_str[i:i + 8] for i in range(0, len(hex_str), 8)])
    result = [f"push 0x{h}" for h in result.split(os.linesep)]
    for h in result:
        print(h)

def main():
    options = get_arguments()
    string = options.input
    str_to_hex_little_endian_push(s=string)


if __name__ == "__main__":
    main()
