#!/bin/bash
# Build test fixtures for Phantom integration tests.
# Requires gcc with static linking support.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cat > /tmp/phantom_hello.c << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello, World!\n");
    return 0;
}
EOF

echo "Building hello_x86_64 (static ELF)..."
gcc -static -o "${SCRIPT_DIR}/hello_x86_64" /tmp/phantom_hello.c
echo "Done: ${SCRIPT_DIR}/hello_x86_64"

rm -f /tmp/phantom_hello.c
