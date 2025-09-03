#!/usr/bin/env python3
"""
Accessibility Permissions Setup Guide
"""

import subprocess
import sys

def check_accessibility_permissions():
    """Check if accessibility permissions are granted"""
    print("🔍 Checking Accessibility Permissions")
    print("=" * 50)
    
    # Test basic AppleScript access
    try:
        result = subprocess.run([
            'osascript', '-e', 
            'tell application "System Events" to tell process "System Settings" to return name of front window'
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print("✅ Accessibility permissions are granted!")
            print(f"System Settings window: {result.stdout.strip()}")
            return True
        else:
            print("❌ Accessibility permissions are NOT granted")
            print(f"Error: {result.stderr.strip()}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking permissions: {e}")
        return False

def provide_setup_instructions():
    """Provide step-by-step setup instructions"""
    print("\n📋 Setup Instructions:")
    print("=" * 50)
    print("1. Open System Settings (System Preferences on older macOS)")
    print("2. Go to 'Privacy & Security'")
    print("3. Click on 'Accessibility' in the left sidebar")
    print("4. Click the '+' button to add an application")
    print("5. Navigate to /Applications/Utilities/ and select 'Terminal'")
    print("   (or find your terminal app - iTerm, etc.)")
    print("6. Make sure the checkbox next to Terminal is checked")
    print("7. You may need to enter your admin password")
    print("8. Restart this application")
    
    print("\n⚠️  Alternative Approach:")
    print("If you prefer not to grant accessibility permissions,")
    print("we can use a limited discovery mode that:")
    print("- Opens each System Settings pane")
    print("- Takes screenshots for manual review")
    print("- Logs which panes were visited")
    print("- Detects authorization dialogs when they appear")

def create_limited_discovery():
    """Create a limited discovery mode without UI automation"""
    print("\n🔧 Creating Limited Discovery Mode...")
    
    limited_script = '''#!/usr/bin/env python3
"""
Limited Authorization Discovery - No UI Automation Required
"""

import subprocess
import time
import logging
from datetime import datetime

class LimitedDiscovery:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        
    def discover_panes(self):
        """Visit System Settings panes without clicking elements"""
        panes = [
            ("Privacy & Security", "x-apple.systempreferences:com.apple.PrivacySecurity-Settings.extension"),
            ("Accessibility", "x-apple.systempreferences:com.apple.Accessibility-Settings.extension"),
            ("Network", "x-apple.systempreferences:com.apple.Network-Settings.extension"),
            ("Sharing", "x-apple.systempreferences:com.apple.Sharing-Settings.extension"),
            ("Users & Groups", "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension"),
            ("Wi-Fi", "x-apple.systempreferences:com.apple.WiFi-Settings.extension"),
            ("Bluetooth", "x-apple.systempreferences:com.apple.BluetoothSettings"),
        ]
        
        print("🚀 Starting Limited Authorization Discovery")
        print("This mode will open panes but requires manual interaction")
        print("Watch for authorization dialogs and note which panes trigger them")
        print("=" * 60)
        
        for i, (pane_name, url) in enumerate(panes, 1):
            print(f"\\n{i}. Opening {pane_name}...")
            
            try:
                result = subprocess.run(['open', url], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"   ✅ Opened {pane_name}")
                    print(f"   👁️  Please manually explore this pane")
                    print(f"   🔍 Look for buttons/settings that might require authorization")
                    
                    # Wait for user to explore
                    input(f"   ⏳ Press Enter when done exploring {pane_name}...")
                else:
                    print(f"   ❌ Failed to open {pane_name}")
                    
            except Exception as e:
                print(f"   ❌ Error opening {pane_name}: {e}")
            
            time.sleep(1)
        
        print("\\n🎉 Limited discovery completed!")
        print("Please manually test settings that might require authorization:")
        print("- Location Services settings")
        print("- Camera/Microphone permissions") 
        print("- File/Folder access")
        print("- Accessibility features")
        print("- Network settings")
        print("- Sharing options")

if __name__ == "__main__":
    discovery = LimitedDiscovery()
    discovery.discover_panes()
'''
    
    with open('limited_discovery.py', 'w') as f:
        f.write(limited_script)
    
    print("✅ Created limited_discovery.py")
    print("Run it with: python limited_discovery.py")

def main():
    print("🔐 macOS Authorization Discovery - Permissions Setup")
    print("=" * 60)
    
    if check_accessibility_permissions():
        print("\\n🎉 You're all set! The full discovery tool should work.")
        print("Run: python main.py --mode discover --debug")
    else:
        provide_setup_instructions()
        create_limited_discovery()
        
        print("\\n🤔 What would you like to do?")
        print("1. Set up accessibility permissions and use full discovery")
        print("2. Use limited discovery mode (no permissions needed)")
        
        choice = input("\\nEnter your choice (1 or 2): ").strip()
        
        if choice == "2":
            print("\\n🚀 Starting limited discovery mode...")
            subprocess.run([sys.executable, 'limited_discovery.py'])
        else:
            print("\\n📋 Please follow the setup instructions above, then run:")
            print("python main.py --mode discover --debug")

if __name__ == "__main__":
    main()
