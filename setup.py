#!/usr/bin/env python3
"""Setup script for Lightweight IDS."""

from setuptools import setup, find_packages

setup(
    name="lightweight-ids",
    version="1.0.0",
    description="Lightweight IDS for small networks and IoT devices",
    author="Security Engineer",
    license="MIT",
    py_modules=["simple_ids", "simple_config"],
    install_requires=[
        "scapy>=2.5.0",
        "PyYAML>=6.0"
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "lightweight-ids=simple_ids:main",
            "ids=simple_ids:main"
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring"
    ]
)
