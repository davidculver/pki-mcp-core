#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== pki-mcp-core demo launcher ==="
echo

# Check Python
if ! command -v python &>/dev/null; then
    echo "ERROR: python not found in PATH"
    exit 1
fi

PYTHON_VERSION=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED="3.10"
if python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
    echo "[OK] Python $PYTHON_VERSION"
else
    echo "ERROR: Python 3.10+ required, found $PYTHON_VERSION"
    exit 1
fi

# Check dependencies
echo -n "[..] Checking dependencies... "
if ! python -c "import cryptography, mcp, ollama" 2>/dev/null; then
    echo "missing. Installing..."
    pip install -r requirements.txt
else
    echo "OK"
fi

# Check Ollama is running
echo -n "[..] Checking Ollama... "
if ! curl -sf "${OLLAMA_BASE_URL:-http://localhost:11434}/api/tags" >/dev/null 2>&1; then
    echo
    echo "ERROR: Ollama is not running."
    echo "  Start it with:  ollama serve"
    exit 1
fi
echo "OK"

# Check llama3.1:8b is available
echo -n "[..] Checking llama3.1:8b model... "
if ! curl -sf "${OLLAMA_BASE_URL:-http://localhost:11434}/api/tags" | grep -q "llama3.1:8b"; then
    echo "not found. Pulling..."
    ollama pull llama3.1:8b
else
    echo "OK"
fi

# Clean up previous run artifacts
echo "[..] Cleaning previous run artifacts..."
rm -f audit.jsonl
rm -rf pki certs

echo
echo "=== Starting demo ==="
echo

python demo.py

echo
echo "=== Audit log saved to: $SCRIPT_DIR/audit.jsonl ==="
