#!/usr/bin/env python3
import os
import typer
from typing import Optional
import pefile
from rich.console import Console
from rich.table import Table

console = Console()


def validate_file(file: str):
    if not os.path.exists(file):
        console.print(f"[-] The file {file} doesn't exist.", style="bold red")
        raise typer.Exit(code=-1)

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
    print(rva)
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
    Print details of each section in the PE file, including their characteristics.
    """
    validate_pe_file(file)

    pe = pefile.PE(file)
    table = Table(title="PE File Sections")
    table.add_column("Section Name", style="cyan")
    table.add_column("Virtual Address", justify="right", style="magenta")
    table.add_column("Virtual Size", justify="right", style="green")
    table.add_column("Raw Size", justify="right", style="green")
    table.add_column("Characteristics", justify="left", style="yellow")

    for section in pe.sections:
        characteristics = describe_section_characteristics(section.Characteristics)
        section_name = section.Name.decode().rstrip('\x00')  # Clean up the section name
        table.add_row(
            section_name,
            hex(section.VirtualAddress),
            hex(section.Misc_VirtualSize),
            hex(section.SizeOfRawData),
            characteristics
        )

    console.print(table)

def describe_section_characteristics(characteristics):
    """
    Return a string describing the section characteristics.
    """
    flags = [
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE'], "Code"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'], "Initialized Data"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA'], "Uninitialized Data"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_DISCARDABLE'], "Discardable"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_NOT_CACHED'], "Not Cached"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_NOT_PAGED'], "Not Paged"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_SHARED'], "Shared"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'], "Execute"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'], "Read"),
        (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'], "Write")
    ]
    characteristics_desc = []
    for flag, desc in flags:
        if characteristics & flag:
            characteristics_desc.append(desc)
    return ", ".join(characteristics_desc)

def search_bytes(file: str, byte_sequence: str):
    """
    Search for a given sequence of bytes in a binary file.
    """
    validate_file(file)

    # Convert string to bytes
    try:
        search_sequence = bytes.fromhex(byte_sequence.replace('\\x', ''))
    except ValueError:
        console.print(f"[-] Invalid byte sequence: {byte_sequence}", style="bold red")
        raise typer.Exit(code=1)

    try:
        with open(file, 'rb') as f:
            file_content = f.read()
    except IOError as e:
        console.print(f"Error reading the file: {str(e)}", style="bold red")
        raise typer.Exit(code=1)

    # Search for the byte sequence in the file content
    index = file_content.find(search_sequence)
    if index == -1:
        console.print("Sequence not found.", style="bold red")
    else:
        table = Table(title="Byte Sequence Found")
        table.add_column("Offset", style="cyan")
        table.add_column("Hex", style="magenta")
        table.add_column("ASCII", style="green")

        # Display the found sequence in a table
        hex_values = search_sequence.hex()
        ascii_values = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in search_sequence])
        row_hex = ' '.join(hex_values[j:j+2] for j in range(0, len(hex_values), 2))
        table.add_row(f"{index:#010x}", row_hex, ascii_values)

        console.print(table)


def display_bytes(file: str, offset: str, length: int):
    """
    Display the specified number of bytes from a given file starting at a specific offset.
    """
    validate_file(file)

    try:
        offset = int(offset, 16) if offset.startswith("0x") else int(offset)
    except ValueError:
        console.print(f"[-] Invalid offset value: {offset}", style="bold red")
        raise typer.Exit(code=1)

    try:
        with open(file, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
    except IOError as e:
        console.print(f"Error accessing the file: {str(e)}", style="bold red")
        raise typer.Exit(code=1)

    table = Table(title="File Bytes Display")
    table.add_column("Offset", style="cyan")
    table.add_column("Hex", style="magenta")
    table.add_column("ASCII", style="green")

    # Display bytes in table
    hex_values = data.hex()
    ascii_values = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])

    # Split hex and ASCII values into manageable chunks
    row_len = 16  # Number of bytes per row in the table
    for i in range(0, len(data), row_len):
        row_hex = ' '.join(hex_values[j:j+2] for j in range(i*2, min((i+row_len)*2, len(hex_values)), 2))
        row_ascii = ascii_values[i:i+row_len]
        table.add_row(f"{offset+i:#010x}", row_hex, row_ascii)

    console.print(table)