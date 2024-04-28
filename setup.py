#!/usr/bin/env python3

version = "1.1.2"

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

REPO_URL = 'https://github.com/totekuh/shellcrafter'


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
            "shellcrafter=shellcrafter.cli:app",
        ],
    },
    url=REPO_URL,
    install_requires=[
        "numpy",  # Depending on your CLI, some of these may no longer be necessary
        "keystone-engine",
        "termcolor",
        "rich",
        "ropper",
        "capstone",
        "typer",
        "pefile"
    ],
    project_urls={  # Optional
        'Bug Reports': f'{REPO_URL}/issues',
        'Source': REPO_URL,
    },
)
