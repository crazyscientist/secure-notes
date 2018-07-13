#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(
    name='securenotes-client-api',
    version='0.1',
    author="Andreas Pritschet",
    description="API wrapper for SecureNotes clients",
    url="https://github.com/crazyscientist/secure-notes",
    packages=find_packages(),
    python_requires=">=3.5",
    install_requires=['requests', 'pycryptodomex']
)