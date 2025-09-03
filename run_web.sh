#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Run web dashboard only
python main.py --mode web --port 5000
