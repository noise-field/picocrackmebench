#!/usr/bin/env python3
"""
Setup script for PyGhidra Crackme Solver
"""

from setuptools import setup, find_packages

setup(
    name="pyghidra-crackme-solver",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="AI-powered crackme solving agent using PyGhidra and multiple LLM frameworks",
    url="https://github.com/yourusername/pyghidra-crackme-solver",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Reverse Engineering",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=[
        "pyghidra",
        "langchain>=0.1.0",
        "langchain-openai",
        "langchain-community",
        "smolagents",
    ],
)