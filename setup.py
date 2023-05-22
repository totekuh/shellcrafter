#!/usr/bin/env python3

version = "1.0.5"

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shellcrafter",
    version=version,
    description="A package containing scripts for developing and generating shellcode",
    long_description=long_description,
    author="totekuh",
    author_email="totekuh@protonmail.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "keyst-api=shellcrafter.keyst_api:main",
            "compute-hashes-from-function-name=shellcrafter.ror_hash:main",
            "find-gadgets=shellcrafter.find_gadgets:main",
            "ascii-to-push=shellcrafter.ascii_hex_stack_push_converter:main",
        ],
    },
    url='https://github.com/totekuh/shellcrafter',  # Optional
    install_requires=[
        "numpy",
        "keystone-engine",
        "termcolor",
        "rich",
        "ropper",
        'capstone'
    ],
    project_urls={  # Optional
        'Bug Reports': 'https://github.com/totekuh/shellcrafter/issues',
        'Source': 'https://github.com/totekuh/shellcrafter',
    },

)
