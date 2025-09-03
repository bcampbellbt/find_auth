#!/usr/bin/env python3
"""
Simple system test to check if basic functionality works
"""

import subprocess
import sys
import time

def test_system_settings():
    """Test if we can open System Settings"""
    print("Testing System Settings access...")
    try:
        result = subprocess.run(['open', '-b', 'com.apple.systempreferences'], 
                               capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ System Settings can be opened")
            return True
        else:
            print(f"❌ Failed to open System Settings: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error opening System Settings: {e}")
        return False

def test_url_scheme():
    """Test if URL schemes work"""
    print("Testing URL scheme navigation...")
    try:
        # Try the modern URL scheme for macOS Sequoia
        result = subprocess.run(['open', 'x-apple.systempreferences:com.apple.General-Settings.extension'], 
                               capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ URL scheme navigation works")
            time.sleep(2)  # Give it time to open
            return True
        else:
            print(f"❌ URL scheme failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error with URL scheme: {e}")
        return False

def test_applescript_basic():
    """Test basic AppleScript functionality"""
    print("Testing basic AppleScript...")
    try:
        script = '''
        tell application "System Settings"
            return name
        end tell
        '''
        result = subprocess.run(['osascript', '-e', script], 
                               capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and "System Settings" in result.stdout:
            print("✅ Basic AppleScript works")
            return True
        else:
            print(f"❌ AppleScript failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error with AppleScript: {e}")
        return False

def main():
    print("🔍 Running System Readiness Test")
    print("=" * 40)
    
    tests = [
        test_system_settings,
        test_url_scheme, 
        test_applescript_basic
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 40)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("✅ System is ready for authorization discovery!")
    else:
        print("⚠️ Some tests failed. Discovery may have limited functionality.")
        print("\nNext steps:")
        print("1. Grant accessibility permissions in System Settings > Privacy & Security > Accessibility")
        print("2. Add Terminal/iTerm to the list of allowed applications")
        print("3. Re-run this test")

if __name__ == "__main__":
    main()
