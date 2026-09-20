#!/bin/sh
# Downloads the CodeQL bundle (~700 MB) into .tools/codeql (used by the CodeQL adapter, run inside a sandbox container).
set -eu
cd "$(dirname "$0")/../.."
mkdir -p .tools
[ -x .tools/codeql/codeql ] && { echo "CodeQL already installed: $(.tools/codeql/codeql version | head -1)"; exit 0; }
curl -fL --retry 3 -o .tools/codeql-bundle.tar.gz https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
tar -xzf .tools/codeql-bundle.tar.gz -C .tools && rm .tools/codeql-bundle.tar.gz
.tools/codeql/codeql version | head -1
