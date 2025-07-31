#!/usr/bin/env python3
"""
Setup script for Botnet Detection Tool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="botnet-detector",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced Botnet Detection Script for Kali Linux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/botnet-detector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "botnet-detector=botnet_detector:main",
        ],
    },
    keywords="security, botnet, network, detection, cybersecurity, kali-linux",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/botnet-detector/issues",
        "Source": "https://github.com/yourusername/botnet-detector",
        "Documentation": "https://github.com/yourusername/botnet-detector/wiki",
    },
)