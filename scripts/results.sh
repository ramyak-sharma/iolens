#!/bin/bash
# builds docs/results.md from whatever is in docs/raw. a check that was
# never run says so instead of being left out
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec python3 "$ROOT/scripts/results.py" "$ROOT/docs/raw"
