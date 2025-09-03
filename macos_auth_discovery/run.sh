#!/bin/bash

# macOS Authorization Discovery Tool
# Simple Flask Web Application Launcher

set -e

echo "=================================================="
echo "macOS Authorization Discovery Tool"
echo "=================================================="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Working directory: $SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
    echo "Virtual environment created."
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "Dependencies installed."
echo "=================================================="

# Run the Flask web application
echo "Starting Flask web server..."
echo "Dashboard: http://localhost:5000"
echo "Press Ctrl+C to stop"
echo "=================================================="

python3 app.py
