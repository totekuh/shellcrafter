#!/usr/bin/env python3
from pprint import pprint
import os
import sys
from keystone import *
from typer import Typer, Option, Exit, Argument, echo

module_path = os.path.dirname(__file__)
sys.path.append(module_path)

from keyst_api import print_shellcode, run_shellcode, eprint
from keyst_api import OUTPUT_FORMAT_PYTHON, X86_ARCH, X64_ARCH
from shellcode_procedure_generator import str_to_hex_little_endian_push, \
    data_types, \
    print_hash_algorithm, \
    compute_hash, \
    generate_load_library, \
    write_to_memory
from find_gadgets import do_find_gadgets

app = Typer(help="Shellcrafter: A tool for shellcode development and gadget finding.", add_completion=False)

shellcode_app = Typer(add_completion=False)
app.add_typer(shellcode_app, name="shellcode", help="Shellcode-related operations.")

codegen_app = Typer(help="Code generation utilities.")
app.add_typer(codegen_app, name="codegen")

gadgets_app = Typer(help="Searches for clean, categorized gadgets from a given list of files.")
app.add_typer(gadgets_app, name="gadgets")

DEFAULT_VAR_NAME = "shellcode"


def read_instructions_from_file(filepath: str) -> str:
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    else:
        print(f"The given file {filepath} doesn't exist")
        raise Exit(code=1)


@codegen_app.command(help="Displays a list of common data types used in Windows programming with their descriptions.")
def print_data_types():
    """
    This command prints a detailed list of data types with their corresponding type, size, and a brief description.
    It is useful for developers needing quick reference to these types during Windows API programming or similar tasks.
    """
    pprint(data_types, indent=4)


@codegen_app.command("print-hash-alg", help="Prints the assembly code for ROR13 hashing algorithm.")
def print_hash_alg():
    print_hash_algorithm()


@codegen_app.command("hash", help="Computes a hash of the given input string.")
def hash_string(input_string: str = Argument(..., help="Input string to compute hash for.")):
    """
    Computes a hash of the input string using assembly logic. This command processes the provided string through
    a hash function implemented in assembly, demonstrating how strings can be transformed into a hash value,
    useful for cryptographic applications and ensuring data integrity.
    """
    compute_hash(input_string)


ascii_option = Option(...,
                      help='Specify the ASCII string to convert to the HEX format '
                           'for putting this onto the stack with `--push-ascii` command '
                           'or to write to memory with `--write` command')
null_free_option = Option(False,
                          help="Avoid NULL bytes in the generated shellcode.")
write_addr_option = Option(...,
                           help='Specify the address to write to in HEX or a relative offset; '
                                'e.g., --write-addr "[ebp-0x50]" or --write-addr "0x51233345"')


@codegen_app.command("write", help="Writes a string to a specific memory address, "
                                   "formatting it in hexadecimal and optionally avoiding NULL bytes.")
def write(ascii_string: str = ascii_option,
          write_addr: str = write_addr_option,
          null_free: bool = null_free_option):
    print(f"push_str:  ;# push the '{ascii_string}' onto the stack")
    write_to_memory(s=ascii_string, write_addr=write_addr, null_free=null_free)


@codegen_app.command("push-ascii", help="Converts an ASCII string to hexadecimal "
                                        "in little-endian for stack pushing.")
def push_for_ascii(
        ascii_string: str = ascii_option,
        null_free: bool = null_free_option):
    print(f"push_str:  ;# push the '{ascii_string}' onto the stack")
    str_to_hex_little_endian_push(s=ascii_string, null_free=null_free)


@codegen_app.command("load-library",
                     help="Generates assembly to load a DLL via LoadLibrary, "
                          "with optional NULL-byte avoidance.")
def load_library(
        dll_name: str = Option(..., help="Specify the DLL name to load."),
        load_library_addr: str = Option(...,
                                        help="Specify the absolute relative offset in HEX of LoadLibraryA function."),
        null_free: bool = null_free_option
):
    """
    Generate instructions for loading a DLL.
    """
    if not dll_name or not load_library_addr:
        echo("Error: --load-library-dll-name and --load-library-addr are required when --load-library is given.",
             err=True)
        raise Exit(code=1)

    generate_load_library(dll_name=dll_name, load_library_func_addr=load_library_addr, null_free=null_free)


@gadgets_app.command()
def find_gadgets(
        files: str = Argument(...,
                              help="Comma-separated list of files to pull gadgets from "
                                   "(optionally, add base address like libspp.dll:0x10000000)."),
        bad_chars: str = Option("",
                                "--bad-chars",
                                help="A list of bad chars to omit from gadgets, e.g., \\x00\\x0a\\x0d",
                                show_default=False),
        arch: str = Option("x86",
                           "--arch",
                           help="Architecture of the given file.", show_default=True),
        output: str = Option("found-gadgets.txt",
                             "--output",
                             help="Name of output file where all gadgets are written.",
                             show_default=True),
        color: bool = Option(False,
                             "--color",
                             help="Colorize gadgets in output.",
                             show_default=True),
        skip_rp: bool = Option(False,
                               "--skip-rp",
                               help="Don't run rp++ to find additional gadgets.",
                               show_default=True)
):
    """
    This command searches for gadgets in the given files, allowing for detailed configuration of what is considered a 'bad character',
    the architecture of the files, and whether to output the results colorized. Additional tools like rp++ can be skipped if specified.
    """
    if bad_chars:
        bad_chars_list = [bc for bc in bad_chars.split("\\x") if bc.strip()]
    else:
        bad_chars_list = []

    do_find_gadgets(files=files.split(","),
                    bad_chars=bad_chars_list,
                    arch=arch,
                    output=output,
                    color=color,
                    skip_rp=skip_rp)


@shellcode_app.command("compile",
                       help="Compiles assembly instructions into executable shellcode, "
                            "with options to execute or print it.")
def compile_shellcode(instructions: str = Option(None, "--instructions", "-i",
                                                 help="Assembly instructions to generate the shellcode"),
                      instructions_file: str = Option(None, "--instructions-file", "-if",
                                                      help="File with assembly instructions to generate the shellcode"),
                      run: bool = Option(False, "--run", "-r", help="Execute the shellcode after compiling"),
                      var_name: str = Option(DEFAULT_VAR_NAME, "--var-name", "-vn",
                                             help="Variable name for the shellcode"),
                      interval: int = Option(48, "--interval",
                                             help="Number of opcodes per line while printing the shellcode", min=0,
                                             max=192),
                      interactive: bool = Option(False, "--interactive", is_flag=True,
                                                 help="Wait for user input before executing the shellcode"),
                      output_format: str = Option(OUTPUT_FORMAT_PYTHON, "--output-format",
                                                  help="Output format of the shellcode: 'python', 'c-array', or 'bin'."),
                      arch: str = Option(X86_ARCH, "--arch",
                                         help=f"Architecture for the assembly: '{X64_ARCH}' or '{X86_ARCH}'.")):
    """
    Compiles assembly instructions into shellcode and optionally executes it.
    """
    if instructions and instructions_file:
        echo("Either the --instructions-file or --instructions option must be given, not both.", err=True)
        raise Exit(code=1)
    if not instructions and not instructions_file:
        echo("Either the --instructions-file or --instructions option must be given.", err=True)
        raise Exit(code=1)

    if instructions_file:
        instructions = read_instructions_from_file(instructions_file)

    # Determine the architecture and mode for the Keystone engine
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
        shellcode_assembled, count = ks.asm(instructions)
        eprint(f"[+] {count} instructions have been encoded")
    except KsError as ks_error:
        eprint(f"Shellcode compilation failed: {ks_error}", err=True)
        raise Exit(code=1)

    if run:
        run_shellcode(encoding=shellcode_assembled,
                      interactive=interactive,
                      arch=arch)
    else:
        print_shellcode(shellcode_assembled, var_name=var_name, interval=interval, output_format=output_format)


if __name__ == "__main__":
    app()
