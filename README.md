# shellcrafter
Scripts, tools and code snippets for exploit development/assembly/shellcoding.

## keyst-api.py

Keystone Shellcode Generator is a Python script that utilizes the Keystone Engine to generate and execute assembly shellcode. 

The script accepts assembly instructions from the command line or a file, and outputs the shellcode in a convenient format for easy copy-pasting. 
Optionally, it can execute the shellcode on a Windows machine using a virtual thread, with the ability to pause execution for debugger attachment.

## ror-hash.py

This Python script computes the hash of a given function name using the ROR (rotate right) operation, specifically designed for shellcode development. 

The script accepts a single function name as an input argument and outputs the computed hash in hexadecimal format. 
These hashes are useful when developing custom shellcode that requires dynamic function resolution, as they can be used for comparison during the function lookup process.

## ascii-hex-stack-push-converter.py

This Python script converts a given ASCII string to its corresponding HEX format and generates the x86 assembly instructions for pushing the string onto the stack in little-endian order. 

The script accepts a single input argument, which is the ASCII string to be converted. 

The output consists of a series of push instructions that can be used in shellcode development to place the string onto the stack.

## find-gadgets.py

Source: https://github.com/epi052/osed-scripts

This script is a Python-based gadget finder for the x86 and x86_64 architectures. 

It searches for clean, categorized gadgets from a given list of files, optionally excluding specific "bad characters" from the gadgets. 

The script is particularly useful for those working with return-oriented programming (ROP) and constructing ROP chains.

## find_ppr_args.wds

The script provided is utilizing the WinDbg scripting language to search for specific byte sequences within a given range.

The script skips the value `0x5c`.

