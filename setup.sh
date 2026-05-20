#!/usr/bin/env bash
# setup.sh — One-time environment setup for file_triage.py
# Run from ~/scripts/nssr/
# Usage: bash setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo ""
echo "  ┌─────────────────────────────────────────┐"
echo "  │   File Triage — Environment Setup        │"
echo "  └─────────────────────────────────────────┘"
echo ""
echo "  Directory : $SCRIPT_DIR"
echo "  Venv      : $VENV_DIR"
echo ""

# Check python3 is available
if ! command -v python3 &>/dev/null; then
    echo "  ERROR: python3 not found. Install with: sudo pacman -S python"
    exit 1
fi

PYTHON_VER=$(python3 --version)
echo "  Python    : $PYTHON_VER"

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo ""
    echo "  Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "  ✓ venv created"
else
    echo "  ✓ venv already exists — skipping creation"
fi

# Activate and install packages
echo ""
echo "  Installing packages..."
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install \
    requests \
    pefile \
    colorama \
    tabulate \
    reportlab \
    --quiet

echo ""
echo "  ✓ All packages installed:"
"$VENV_DIR/bin/pip" list | grep -E "requests|pefile|colorama|tabulate|reportlab"

# Create the run wrapper
WRAPPER="$SCRIPT_DIR/triage"
cat > "$WRAPPER" << 'EOF'
#!/usr/bin/env bash
# triage — wrapper to run file_triage.py inside the venv
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/file_triage.py" "$@"
EOF
chmod +x "$WRAPPER"

echo ""
echo "  ✓ Run wrapper created: ./triage"
echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │  Setup complete! Usage:                                  │"
echo "  │                                                          │"
echo "  │  ./triage suspicious.exe                                 │"
echo "  │  ./triage setup.exe --pdf                                │"
echo "  │  ./triage setup.exe --pdf /tmp/report.pdf                │"
echo "  │                                                          │"
echo "  │  With API keys:                                          │"
echo "  │  export VIRUSTOTAL_API_KEY=your_key                      │"
echo "  │  export OTX_API_KEY=your_key                             │"
echo "  │  ./triage setup.exe --pdf                                │"
echo "  │                                                          │"
echo "  │  Or activate the venv manually:                          │"
echo "  │  source .venv/bin/activate                               │"
echo "  │  python file_triage.py setup.exe --pdf                   │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
