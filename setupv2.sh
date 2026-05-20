#!/usr/bin/env bash
# setup.sh — One-time environment setup for file_triage.py
# Run from ~/scripts/nssr/
# Usage: bash setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

echo ""
echo "  ┌─────────────────────────────────────────┐"
echo "  │   File Triage — Environment Setup        │"
echo "  └─────────────────────────────────────────┘"
echo ""
echo "  Directory : $SCRIPT_DIR"
echo "  Venv      : $VENV_DIR"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "  ERROR: python3 not found. Install with: sudo pacman -S python"
    exit 1
fi

PYTHON_VER=$(python3 --version)
echo "  Python    : $PYTHON_VER"

if [ ! -d "$VENV_DIR" ]; then
    echo ""
    echo "  Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "  ✓ venv created"
else
    echo "  ✓ venv already exists — skipping creation"
fi

echo ""
echo "  Installing packages..."
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install \
    requests \
    pefile \
    colorama \
    tabulate \
    reportlab \
    beautifulsoup4 \
    --quiet

echo ""
echo "  ✓ All packages installed:"
"$VENV_DIR/bin/pip" list | grep -E "requests|pefile|colorama|tabulate|reportlab|beautifulsoup4"

WRAPPER="$SCRIPT_DIR/triage"
cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/usr/bin/env bash
# triage — wrapper to run file_triage.py inside the venv
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/file_triage.py" "$@"
WRAPPER_EOF
chmod +x "$WRAPPER"

echo ""
echo "  ✓ Run wrapper created: ./triage"
echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │  Setup complete! Usage:                                  │"
echo "  │                                                          │"
echo "  │  ./triage suspicious.exe                                 │"
echo "  │  ./triage setup.exe --app-name 'Zoom' --pdf             │"
echo "  │  ./triage setup.exe --app-name 'AnyDesk' --version 8.0  │"
echo "  │                                                          │"
echo "  │  Optional env vars:                                      │"
echo "  │  export VIRUSTOTAL_API_KEY=your_key                      │"
echo "  │  export OTX_API_KEY=your_key                             │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
