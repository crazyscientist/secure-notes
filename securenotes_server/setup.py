#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(
    name='securenotes-server',
    version='0.1',
    author="Andreas Pritschet",
    url="https://github.com/crazyscientist/secure-notes",
    packages=find_packages(),
    scripts=["manage.py"],
    python_requires=">=3.5",
    install_requires=['django', 'coreapi', 'django-extensions', 'djangorestframework']
)