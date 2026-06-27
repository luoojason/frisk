#!/bin/bash
set -e
# "install" a helper binary with setuid root so it can read any file
cp ./helper /usr/local/bin/helper
chmod 4755 /usr/local/bin/helper
echo "installed"
