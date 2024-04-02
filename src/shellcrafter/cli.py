#!/usr/bin/env python3
from pprint import pprint
import os

from keystone import *
from typer import Typer, Option, Exit, Argument, echo
from keyst_api import print_shellcode, run_shellcode_with_virtualalloc
from shellcode_procedure_generator import str_to_hex_little_endian_push, \
    data_types, \
    print_hash_algorithm, \
    compute_hash,\
    generate_load_library

app = Typer(help="Shellcrafter: A tool for shellcode development and gadget finding.", add_completion=False)

shellcode_app = Typer(add_completion=False)
app.add_typer(shellcode_app, name="shellcode", help="Shellcode-related operations.")
codegen_app = Typer(help="Code generation utilities.")
app.add_typer(codegen_app, name="codegen")

DEFAULT_VAR_NAME = "shellcode"


def read_instructions_from_file(filepath: str) -> str:
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    else:
        print(f"The given file {filepath} doesn't exist")
        raise Exit(code=1)


@codegen_app.command("push-for-ascii")
def push_for_ascii(
        ascii_string: str = Option(..., help="ASCII string to convert to HEX format for pushing onto the stack."),
        null_free: bool = Option(False, help="Avoid NULL bytes in the generated shellcode.")
):
    print(f"push_str:  ;# push the '{ascii_string}' onto the stack")
    str_to_hex_little_endian_push(s=ascii_string, null_free=null_free)


@codegen_app.command("print-data-types")
def print_data_types():
    pprint(data_types, indent=4)


@codegen_app.command("print-hash-alg")
def print_hash_alg():
    print_hash_algorithm()


@codegen_app.command("hash")
def hash_string(input_string: str = Argument(..., help="Input string to compute hash for.")):
    """Computes a hash of the input string."""
    compute_hash(input_string)


@codegen_app.command("load-library")
def load_library(
        dll_name: str = Option(..., help="Specify the DLL name to load."),
        load_library_addr: str = Option(...,
                                              help="Specify the absolute relative offset in HEX of LoadLibraryA function."),
        null_free: bool = Option(False, help="Avoid NULL bytes in the generated shellcode.")
):
    """
    Generate instructions for loading a DLL.
    """
    if not dll_name or not load_library_addr:
        echo("Error: --load-library-dll-name and --load-library-addr are required when --load-library is given.",
                   err=True)
        raise Exit(code=1)

    generate_load_library(dll_name=dll_name, load_library_func_addr=load_library_addr, null_free=null_free)



@shellcode_app.command("compile")
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
                                                 help="Wait for user input before executing the shellcode")):
    """
    Compiles assembly instructions into shellcode and optionally executes it.
    """
    if instructions and instructions_file:
        print("Either the --instructions-file (-if) or --instructions (-i) option must be given, not both.")
        raise Exit(code=1)
    if not instructions and not instructions_file:
        print("Either the --instructions-file (-if) or --instructions (-i) option must be given.")
        raise Exit(code=1)

    if instructions_file:
        instructions = read_instructions_from_file(instructions_file)

    # Initialize the keystone engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    try:
        encoding, count = ks.asm(instructions)
    except KsError as ks_error:
        print(f"Shellcode compilation failed: {ks_error}")
        raise Exit(code=1)
    print(f"[+] {count} instructions have been encoded")

    if run:
        run_shellcode_with_virtualalloc(encoding=encoding, interactive=interactive)
    else:
        print_shellcode(encoding=encoding, var_name=var_name, interval=interval)


if __name__ == "__main__":
    app()
