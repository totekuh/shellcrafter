#!/usr/bin/env python3

version = "1.0.11"

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shellcrafter",
    version=version,
    description="A package containing scripts for developing and generating shellcode",
    long_description=long_description,
    long_description_content_type='text/markdown',  # Add this line
    author="totekuh",
    author_email="totekuh@protonmail.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "keyst-api=shellcrafter.keyst_api:main",
            "find-gadgets=shellcrafter.find_gadgets:main",
            "shellcode-procedure-generator=shellcrafter.shellcode_procedure_generator:main",
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
