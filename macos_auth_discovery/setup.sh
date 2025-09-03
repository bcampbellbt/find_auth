#!/bin/bash

# macOS Authorization Discovery Tool Setup Script
# This script sets up the environment and installs dependencies

set -e  # Exit on any error

echo "🔍 macOS Authorization Discovery Tool Setup"
echo "============================================"

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ Error: This tool is designed for macOS only."
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
python_major=$(echo $python_version | cut -d. -f1)
python_minor=$(echo $python_version | cut -d. -f2)

# Check if Python 3.8+
if [[ $python_major -lt 3 ]] || [[ $python_major -eq 3 && $python_minor -lt 8 ]]; then
    echo "❌ Error: Python 3.8+ required. Current version: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "📥 Installing Python dependencies..."

# Core dependencies
pip install Flask==2.3.3
pip install Werkzeug==2.3.7
pip install Jinja2==3.1.2
pip install requests==2.31.0

# PyObjC frameworks for macOS integration
echo "🍎 Installing PyObjC frameworks..."

# Install basic PyObjC (latest versions that work with current Python)
echo "📦 Installing core PyObjC..."
pip install pyobjc-core || echo "⚠️  PyObjC core installation failed, will use fallback methods"

echo "📦 Installing Cocoa framework..."
pip install pyobjc-framework-Cocoa || echo "⚠️  Cocoa framework not available, will use fallback methods"

echo "📦 Installing Security framework..."
pip install pyobjc-framework-Security || echo "⚠️  Security framework not available, will use fallback methods"

echo "📦 Installing ApplicationServices framework..."
pip install pyobjc-framework-ApplicationServices || echo "⚠️  ApplicationServices framework not available, will use fallback methods"

echo "📦 Installing Accessibility framework..."
pip install pyobjc-framework-Accessibility || echo "⚠️  Accessibility framework not available, will use fallback methods"

echo "📦 Attempting IOKit framework installation..."
pip install pyobjc-framework-IOKit || echo "⚠️  IOKit framework not available, hardware detection will use system commands"

echo "✅ PyObjC installation completed with available frameworks"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data
mkdir -p logs

# Create data directory if it doesn't exist
if [ ! -d "data" ]; then
    mkdir data
    echo "✅ Created data directory"
fi

# Create logs directory if it doesn't exist
if [ ! -d "logs" ]; then
    mkdir logs
    echo "✅ Created logs directory"
fi

# Set up permissions
echo "🔐 Setting up permissions..."

# Check if we have necessary permissions
if ! /usr/bin/log show --last 1s > /dev/null 2>&1; then
    echo "⚠️  Warning: Limited log access. Some features may be restricted."
    echo "   You may need to grant Terminal/iTerm additional permissions in System Preferences > Privacy & Security"
fi

# Create startup script
echo "📝 Creating startup script..."
cat > run.sh << 'EOF'
#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Run the application
python main.py "$@"
EOF

chmod +x run.sh

# Create launch script for web-only mode
cat > run_web.sh << 'EOF'
#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Run web dashboard only
python main.py --mode web --port 5000
EOF

chmod +x run_web.sh

# Create discovery-only script
cat > run_discovery.sh << 'EOF'
#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Run discovery only (no web interface)
python main.py --mode discover
EOF

chmod +x run_discovery.sh

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "   1. Grant necessary permissions in System Preferences:"
echo "      - Privacy & Security > Accessibility (for UI automation)"
echo "      - Privacy & Security > Developer Tools (for terminal access)"
echo "   2. Run the application:"
echo "      ./run.sh                    # Full application (discovery + web)"
echo "      ./run_web.sh               # Web dashboard only"
echo "      ./run_discovery.sh         # Discovery only"
echo ""
echo "🌐 Web dashboard will be available at: http://localhost:5000"
echo ""
echo "⚠️  Important Notes:"
echo "   - Ensure System Settings is not open before starting discovery"
echo "   - The discovery process may take 30-45 minutes to complete"
echo "   - Some authorization detection requires administrator privileges"
echo "   - Results will be saved in the 'data' directory"
echo ""
echo "🔗 For more information, check the README.md file"
