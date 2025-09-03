#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Run discovery only (no web interface)
python main.py --mode discover
