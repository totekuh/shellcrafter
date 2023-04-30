# Shellcrafter

Shellcrafter is a package containing scripts for developing and generating shellcode. 

It provides a collection of utilities for working with shellcode in various ways, such as generating shellcode from assembly instructions, computing hashes from function names, and converting ASCII text to hex stack push instructions.

## Installation

To install Shellcrafter, clone the repository and run:

```bash
pip install .
```

## Usage

Shellcrafter provides the following command-line utilities:

- `keyst-api`: A shellcode generator using the Keystone Engine to assemble assembly instructions into shellcode.
- `compute-hashes-from-function-name`: Computes the hash for a given function name using the ROR operation.
- `ascii-to-push`: Converts an ASCII string to a series of x86 PUSH instructions that represent the given string as hexadecimal values.

To get help on how to use each utility, run the corresponding command with the `-h` or `--help` flag:

```bash
keyst-apir --help
compute-hashes-from-function-name --help
ascii-to-push --help
```
