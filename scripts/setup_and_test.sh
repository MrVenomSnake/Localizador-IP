#!/usr/bin/env bash
# Cross-platform POSIX shell script for macOS / Linux
# Creates venv in .venv, installs dependencies and runs pytest.
# Usage: ./scripts/setup_and_test.sh [--recreate]

set -euo pipefail
RECREATE=0
for arg in "$@"; do
  case "$arg" in
    --recreate) RECREATE=1 ;;
    -h|--help)
      echo "Usage: $0 [--recreate]"
      exit 0
      ;;
    *) ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VENV_PATH="$REPO_ROOT/.venv"
PY="$VENV_PATH/bin/python"

if [ "$RECREATE" -eq 1 ] && [ -d "$VENV_PATH" ]; then
  echo "Removing existing virtual environment at $VENV_PATH..."
  rm -rf "$VENV_PATH"
fi

if [ ! -x "$PY" ]; then
  echo "Creating virtual environment at $VENV_PATH..."
  python3 -m venv "$VENV_PATH"
fi

if [ ! -x "$PY" ]; then
  echo "ERROR: Python not found in venv. Ensure python3 is installed and on PATH." >&2
  exit 1
fi

echo "Using Python: $PY"

echo "Upgrading pip..."
"$PY" -m pip install --upgrade pip

if [ -f "requirements.txt" ]; then
  echo "Installing runtime dependencies from requirements.txt..."
  "$PY" -m pip install -r requirements.txt
else
  echo "Warning: requirements.txt not found. Skipping runtime deps install." >&2
fi

if [ -f "requirements-dev.txt" ]; then
  echo "Installing dev/test dependencies from requirements-dev.txt..."
  "$PY" -m pip install -r requirements-dev.txt
else
  echo "Warning: requirements-dev.txt not found. Skipping dev deps install." >&2
fi

echo "Running tests (pytest)..."
"$PY" -m pytest -q

RET=$?
if [ $RET -ne 0 ]; then
  echo "ERROR: Tests failed with exit code $RET" >&2
  exit $RET
fi

echo "All tests passed ✅"
exit 0
