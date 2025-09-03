# Check if Terminal/iTerm is checked in Accessibility
echo "🔒 Checking Accessibility permissions for Terminal/iTerm..."
osascript -e 'tell application "System Events"
	set uiEnabled to UI elements enabled
end tell
return uiEnabled' 2>/dev/null | grep -q 'true'
if [ $? -ne 0 ]; then
	echo "❌ Accessibility API is not enabled."
	echo "   Please enable 'System Events' scripting and check Terminal/iTerm in System Settings > Privacy & Security > Accessibility."
	echo "   Then re-run this script."
	exit 1
else
	echo "✅ Accessibility API is enabled."
fi
#!/bin/bash


# Activate virtual environment from parent directory
source ../venv/bin/activate


# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"


# Run discovery only (no web interface)
python main.py --mode discover
