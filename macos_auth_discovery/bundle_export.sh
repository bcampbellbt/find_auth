#!/bin/bash

# macOS Authorization Discovery Tool - Bundle Export Script
# Creates a portable, self-contained bundle for distribution

set -e

echo "=================================================="
echo "macOS Authorization Discovery Tool - Bundle Export"
echo "Creating portable distribution bundle..."
echo "=================================================="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Generate timestamp for unique bundle name
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BUNDLE_NAME="macos_auth_discovery_${TIMESTAMP}"
BUNDLE_DIR="/tmp/${BUNDLE_NAME}"
BUNDLE_FILE="${SCRIPT_DIR}/${BUNDLE_NAME}.tar.gz"

echo "Bundle name: ${BUNDLE_NAME}"
echo "Working directory: ${SCRIPT_DIR}"

# Clean up any existing bundle directory
if [ -d "$BUNDLE_DIR" ]; then
    rm -rf "$BUNDLE_DIR"
fi

# Create bundle directory
mkdir -p "$BUNDLE_DIR"

echo "✅ Created bundle directory: ${BUNDLE_DIR}"

# Copy essential files
echo "📦 Copying project files..."

# Core application files (these will be replaced/fixed as needed)
cp config.json "$BUNDLE_DIR/"
cp requirements.txt "$BUNDLE_DIR/"
cp run.sh "$BUNDLE_DIR/"
cp README.md "$BUNDLE_DIR/"
cp LICENSE "$BUNDLE_DIR/"

# Copy source code directory (preserve structure)
cp -r src "$BUNDLE_DIR/"

# Copy documentation directory (preserve structure)
cp -r docs "$BUNDLE_DIR/"

# Copy test files
cp test_pane_discovery.py "$BUNDLE_DIR/"

echo "✅ Core files copied"

# Fix the app.py import issue for the bundle
echo "🔧 Creating bundle-optimized app.py..."
cat > "$BUNDLE_DIR/app.py" << 'EOF'
#!/usr/bin/env python3
"""
Simple Flask Web Application Entry Point
Run the macOS Authorization Discovery Tool web dashboard
"""

import sys
import os
import logging

# Add the current directory to the path so we can import from src
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from src.web.app import create_app

def main():
    """Main entry point for the web application"""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create Flask app
    app = create_app()
    
    # Read configuration
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.exists(config_path):
        import json
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        host = config.get('host', '127.0.0.1')
        port = config.get('port', 5000)
        debug = config.get('debug', False)
    else:
        host = '127.0.0.1'
        port = 5000
        debug = False
    
    print(f"Starting server on http://{host}:{port}")
    
    try:
        # Run the Flask development server
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=False  # Disable reloader in bundle
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
EOF

echo "✅ Bundle app.py created"

# Create a simplified gitignore for the bundle
cat > "$BUNDLE_DIR/.gitignore" << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# macOS
.DS_Store

# Logs
*.log
logs/

# Bundle exports
*.tar.gz
EOF

echo "✅ Bundle .gitignore created"

echo "✅ Using existing run.sh script (no bundle-specific runner needed)"

# Create bundle README
cat > "$BUNDLE_DIR/BUNDLE_README.md" << 'EOF'
# macOS Authorization Discovery Tool - Portable Bundle

This is a portable, self-contained bundle of the macOS Authorization Discovery Tool.

## Quick Start

1. **Extract the bundle:**
   ```bash
   tar -xzf macos_auth_discovery_*.tar.gz
   cd macos_auth_discovery_*
   ```

2. **Run the tool:**
   ```bash
   ./run.sh
   ```

3. **Access the web interface:**
   - Open your browser to: http://localhost:5000
   - Or the tool will attempt to open it automatically

## Requirements

- **macOS 10.15+** (Catalina or later)
- **Python 3.8+** (will be checked automatically)
- **Internet connection** (for initial dependency installation)

## What This Bundle Includes

- ✅ Complete source code
- ✅ Configuration files
- ✅ Documentation
- ✅ Automated setup script
- ✅ Requirements specification
- ✅ Self-contained runner

## Troubleshooting

### Port 5000 in use
If port 5000 is busy, the tool will attempt to use an alternative port automatically.

### Python version issues
Ensure you have Python 3.8 or later installed:
```bash
python3 --version
```

### Permission issues
Make sure the run script is executable:
```bash
chmod +x run.sh
```

## Bundle Features

- 🚀 **One-command setup**: Just run `./run.sh`
- 📦 **Portable**: No repository access required
- 🔒 **Self-contained**: All dependencies managed automatically
- 🧪 **Perfect for testing**: Ideal for VMs and test environments
- 📱 **Team distribution**: Easy to share with team members

---

For more information, see the main README.md file.
EOF

echo "✅ Bundle README created"

# Create the compressed bundle
echo "🗜️  Creating compressed bundle..."
cd /tmp
tar -czf "$BUNDLE_FILE" "$BUNDLE_NAME/"

# Get bundle size
BUNDLE_SIZE=$(du -h "$BUNDLE_FILE" | cut -f1)
BUNDLE_SIZE_BYTES=$(stat -f%z "$BUNDLE_FILE" 2>/dev/null || stat -c%s "$BUNDLE_FILE" 2>/dev/null || echo "unknown")

echo "✅ Bundle created successfully!"
echo ""
echo "=================================================="
echo "📦 BUNDLE EXPORT COMPLETE"
echo "=================================================="
echo "Bundle file: ${BUNDLE_FILE}"
echo "Bundle size: ${BUNDLE_SIZE} (${BUNDLE_SIZE_BYTES} bytes)"
echo "Timestamp: ${TIMESTAMP}"
echo ""
echo "🚀 To use this bundle:"
echo "1. Copy ${BUNDLE_NAME}.tar.gz to your target system"
echo "2. Extract: tar -xzf ${BUNDLE_NAME}.tar.gz" 
echo "3. Run: cd ${BUNDLE_NAME} && ./run.sh"
echo ""
echo "📱 Perfect for VM testing and team distribution!"
echo "=================================================="

# Clean up temporary directory
rm -rf "$BUNDLE_DIR"

# Make the bundle file readable
chmod 644 "$BUNDLE_FILE"

echo "🧹 Temporary files cleaned up"
echo "✅ Bundle export complete!"
