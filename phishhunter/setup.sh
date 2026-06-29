#!/usr/bin/env bash
# Setup script for Kali Linux / Debian / Ubuntu / macOS.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# This creates a virtual environment, installs dependencies, and creates
# a .env file with placeholder values if one doesn't exist yet.

set -e

echo "=== PhishHunter — Setup (Kali/Linux) ==="

# Pick whichever Python 3 is available
if command -v python3 &> /dev/null; then
    PYTHON_BIN=python3
elif command -v python &> /dev/null; then
    PYTHON_BIN=python
else
    echo "ERROR: Python 3 not found. Install it first:"
    echo "  sudo apt update && sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

echo "Using $($PYTHON_BIN --version)"

# Kali ships Python without venv/pip by default on some images — make sure
# the venv module is actually usable before relying on it.
if ! $PYTHON_BIN -c "import venv" &> /dev/null; then
    echo "ERROR: python3-venv is not installed. Install it with:"
    echo "  sudo apt update && sudo apt install python3-venv python3-pip"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    $PYTHON_BIN -m venv venv
else
    echo "Virtual environment already exists, skipping creation."
fi

echo "Activating virtual environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# Create .env with placeholders if missing
if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# VirusTotal API key (free tier works) — get one at https://www.virustotal.com/gui/my-apikey
# Without this, VirusTotal reputation checks and IOC lookups will be skipped gracefully.
VT_API_KEY=your_virustotal_api_key_here

# Optional: set to DEBUG for verbose logging of every scanner module
LOG_LEVEL=INFO
EOF
    echo ""
    echo "Created .env with placeholder values."
    echo "Edit .env and add your VirusTotal API key (VT_API_KEY) — optional but recommended."
else
    echo ".env already exists, leaving it as-is."
fi

# Ensure runtime directories exist (gitignored, so they won't exist on a fresh clone)
mkdir -p reports/_scan_cache

echo ""
echo "=== Setup complete ==="
echo "To run the app:"
echo "  source venv/bin/activate"
echo "  uvicorn app:app --reload"
echo ""
echo "Then open http://127.0.0.1:8000 in your browser."
