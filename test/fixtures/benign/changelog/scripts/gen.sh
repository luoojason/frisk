#!/bin/bash
set -e
git log --pretty=format:"- %s" "$(git describe --tags --abbrev=0)"..HEAD
