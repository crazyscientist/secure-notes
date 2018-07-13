#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(
    name='securenotes-client-cli',
    version='0.1',
    author="Andreas Pritschet",
    description="Command line client for SecureNotes",
    url="https://github.com/crazyscientist/secure-notes",
    packages=find_packages(),
    python_requires=">=3.5",
    scripts=["securenotes.py",],
    install_requires=['securenotes-client-api']
)