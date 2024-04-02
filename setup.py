#!/usr/bin/env python3

version = "1.0.18"

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shellcrafter",
    version=version,
    description="A package containing scripts for developing and generating shellcode",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="totekuh",
    author_email="totekuh@protonmail.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "shellcrafter=shellcrafter.cli:main",  # Adjusted to point to the new unified CLI entry point
        ],
    },
    url='https://github.com/totekuh/shellcrafter',  # Optional
    install_requires=[
        "numpy",  # Depending on your CLI, some of these may no longer be necessary
        "keystone-engine",
        "pprint",
        "termcolor",
        "rich",
        "ropper",
        "capstone",
        "typer",  # Added Typer to the list of required packages
    ],
    project_urls={  # Optional
        'Bug Reports': 'https://github.com/totekuh/shellcrafter/issues',
        'Source': 'https://github.com/totekuh/shellcrafter',
    },
)
