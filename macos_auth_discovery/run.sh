#!/bin/bash

# macOS Authorization Discovery Tool
# Automated Setup and Launch Script

set -e

echo "=================================================="
echo "macOS Authorization Discovery Tool"
echo "Team Setup & Launch Script"
echo "=================================================="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Working directory: $SCRIPT_DIR"

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed or not in PATH"
    echo "💡 Please install Python 3.8+ from https://python.org"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✅ Found Python $PYTHON_VERSION"

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ This tool is designed for macOS"
    exit 1
fi

echo "✅ Running on macOS"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip and install dependencies
echo "Installing/updating dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "✅ Dependencies installed"

# Run setup verification
if [ -f "setup_check.py" ]; then
    echo "Running system compatibility check..."
    python3 setup_check.py
    echo ""
fi

echo "=================================================="
echo "🚀 Starting Web Dashboard"
echo "=================================================="
echo "Dashboard URL: http://localhost:5000"
echo "Press Ctrl+C to stop the server"
echo ""
echo "💡 First time setup:"
echo "   1. Open System Settings > Privacy & Security"
echo "   2. Grant 'Full Disk Access' to Terminal.app"
echo "   3. Restart this tool for full functionality"
echo "=================================================="

# Run the Flask web application
python3 app.py
