#!/bin/bash
# Compatibility wrapper for the manifest-driven fixture builder.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "${SCRIPT_DIR}/build_fixtures.py" "$@"
