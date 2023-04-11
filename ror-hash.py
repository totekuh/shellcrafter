#!/usr/bin/python3
import numpy


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(description='Compute Hashes From Function Names')
    parser.add_argument('-f',
                        '--function',
                        dest='function',
                        required=True,
                        type=str,
                        help="Specify the function's name to compute its hash using the ROR operation")
    options = parser.parse_args()
    return options


def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return int(binb, 2)


def main():
    options = get_arguments()
    function_name = options.function

    edx = 0x00
    ror_count = 0
    for eax in function_name:
        edx = edx + ord(eax)
        if ror_count < len(function_name) - 1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    print(hex(edx))


if __name__ == '__main__':
    main()
