#!/usr/bin/env python3
import os
import typer
from typing import Optional
import pefile
from rich.console import Console
from rich.table import Table

console = Console()


def is_valid_pe_file(file_path: str) -> bool:
    try:
        pefile.PE(file_path)
        return True
    except pefile.PEFormatError as e:
        console.print(f"Error: {str(e)}", style="bold red")
        return False


def validate_pe_file(file: str):
    if not os.path.exists(file):
        console.print(f"[-] The file {file} doesn't exist.", style="bold red")
        raise typer.Exit(code=-1)
    if not is_valid_pe_file(file):
        console.print("[-] The file is not a valid PE file or is a DOS file.", style="bold red")
        raise typer.Exit(code=1)


def find_rva_offset(file: str,
                    rva: str,
                    section_name: Optional[str]):
    """
    Convert RVA to file offset in a PE file.
    """
    validate_pe_file(file)
    try:
        rva_int = int(rva, 16) if rva.startswith("0x") else int(rva)
    except ValueError:
        console.print(f"[-] Invalid RVA value: {rva}", style="bold red")
        raise typer.Exit(code=1)

    parsed_pe_file = pefile.PE(file)
    table = Table(title="RVA Offset Finder")
    table.add_column("Section", style="dim", width=12)
    table.add_column("Virtual Address", justify="right", style="magenta")
    table.add_column("File Offset", justify="right", style="green")

    found = False
    for section in parsed_pe_file.sections:
        section_name_decoded = section.Name.decode().strip()
        if section_name and section_name not in section_name_decoded:
            continue
        if section.contains_rva(rva_int):
            offset = section.get_offset_from_rva(rva_int)
            table.add_row(section_name_decoded,
                          hex(section.VirtualAddress),
                          f"0x{offset:x}")
            found = True
            break

    if found:
        console.print(table)
    else:
        console.print("[-] RVA not found in any section", style="bold red")


def iat_print(file: str,
              dll: Optional[str],
              function: Optional[str]):
    """
    Print the Import Address Table (IAT), optionally filtering by DLL name and/or function name.
    """
    validate_pe_file(file)

    pe = pefile.PE(file)
    table = Table(title="Import Address Table (IAT)")
    table.add_column("DLL Name", justify="left", style="cyan")
    table.add_column("Address", justify="right", style="magenta")
    table.add_column("Function", justify="left", style="green")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode().lower() if entry.dll else "n/a"
            # Filter by DLL name if --dll option is used
            if dll and dll.lower() not in dll_name:
                continue

            for imp in entry.imports:
                function_name = imp.name.decode().lower() if imp.name else "n/a"
                # Further filter by function name if --function option is used
                if function and function.lower() not in function_name:
                    continue

                table.add_row(entry.dll.decode(), f"0x{imp.address:x}", imp.name.decode() if imp.name else "n/a")

    console.print(table)


# def iat_edit(
#         file: str,
#         dll: str,
#         old_address: str,
#         function_name: str,
#         new_address: str):
#     """
#     This command allows for the patching of an Import Address Table (IAT) entry within a Portable Executable (PE) file.
#     Specify the DLL name, old function address, the function name, and the new address to effectively patch the PE file.
#
#     The command verifies the existence of the specified IAT entry before making any modifications.
#     After successful validation and modification, it saves the patched PE file with a '.patched' suffix to denote the change.
#
#     Note: Ensure that the provided addresses and DLL names are accurate to prevent incorrect modifications.
#     """
#     validate_pe_file(file)
#
#     pe = pefile.PE(file)
#     modified = False
#     target_old_address = int(old_address, 16)
#     target_new_address = int(new_address, 16)
#
#     for entry in pe.DIRECTORY_ENTRY_IMPORT:
#         if dll.lower() == entry.dll.decode().lower():
#             for imp in entry.imports:
#                 if function_name.lower() == imp.name.decode().lower() and imp.address == target_old_address:
#                     console.print(f"Original address of {function_name}: {hex(imp.address)}")
#                     # Directly modify the address
#                     imp.address = target_new_address
#                     modified = True
#                     console.print(f"New address of {function_name}: {hex(imp.address)}", style="bold green")
#                     break
#     if modified:
#         pe.write(filename=f"{file}.patched")
#         console.print(f"Modified PE file saved as {file}.patched", style="bold green")
#     else:
#         console.print("Specified entry not found. No modifications made.", style="bold red")


def parse_eat(file: str):
    """
    Parse the Export Address Table (EAT) and print it.
    """
    validate_pe_file(file)

    pe = pefile.PE(file)
    table = Table(title="Export Address Table (EAT)")
    table.add_column("Address", justify="right", style="magenta")
    table.add_column("Name", justify="left", style="green")

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            table.add_row(f"0x{exp.address:x}", exp.name.decode() if exp.name else "n/a")

    console.print(table)


def print_sections(file: str):
    """
    Print details of each section in the PE file.
    """
    validate_pe_file(file)

    pe = pefile.PE(file)
    table = Table(title="PE File Sections")
    table.add_column("Section Name", style="cyan")
    table.add_column("Virtual Address", justify="right", style="magenta")
    table.add_column("Virtual Size", justify="right", style="green")
    table.add_column("Raw Size", justify="right", style="green")

    for section in pe.sections:
        section_name = section.Name.decode().rstrip('\x00')  # Clean up the section name
        table.add_row(
            section_name,
            hex(section.VirtualAddress),
            hex(section.Misc_VirtualSize),
            hex(section.SizeOfRawData)
        )

    console.print(table)
