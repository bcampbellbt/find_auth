#!/usr/bin/env python3
"""
Test script to verify the macOS Authorization Discovery Tool setup
"""

import sys
import os
import subprocess
import platform

def test_python_version():
    """Test Python version compatibility"""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✅ Python version: {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"❌ Python version too old: {version.major}.{version.minor}.{version.micro}")
        return False

def test_macos_version():
    """Test macOS version compatibility"""
    if platform.system() != 'Darwin':
        print("❌ Not running on macOS")
        return False
    
    version = platform.mac_ver()[0]
    print(f"✅ macOS version: {version}")
    return True

def test_dependencies():
    """Test required dependencies"""
    required_modules = [
        'flask',
        'objc',
        'Foundation',
        'AppKit',
        'Security'
    ]
    
    results = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module}: Available")
            results.append(True)
        except ImportError:
            print(f"⚠️  {module}: Not available (will use fallback methods)")
            results.append(False)
    
    return any(results)  # At least some dependencies should be available

def test_permissions():
    """Test basic permission requirements"""
    tests = []
    
    # Test log access
    try:
        result = subprocess.run(['log', 'show', '--last', '1s'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ System log access: Available")
            tests.append(True)
        else:
            print("⚠️  System log access: Limited")
            tests.append(False)
    except Exception:
        print("⚠️  System log access: Not available")
        tests.append(False)
    
    # Test AppleScript execution
    try:
        result = subprocess.run(['osascript', '-e', 'tell application "Finder" to get version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ AppleScript execution: Available")
            tests.append(True)
        else:
            print("⚠️  AppleScript execution: Limited")
            tests.append(False)
    except Exception:
        print("⚠️  AppleScript execution: Not available")
        tests.append(False)
    
    return any(tests)

def test_core_modules():
    """Test core module imports"""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    
    try:
        from core.hardware_profile import HardwareProfileManager
        print("✅ Hardware Profile Manager: Importable")
        
        # Test hardware detection
        hw_manager = HardwareProfileManager()
        profile = hw_manager.get_hardware_profile()
        print(f"   Hardware model: {profile.get('model', 'Unknown')}")
        return True
        
    except Exception as e:
        print(f"❌ Core modules: Import error - {e}")
        return False

def test_web_modules():
    """Test web module imports"""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    
    try:
        from web.app import create_app
        print("✅ Web modules: Importable")
        
        # Test Flask app creation
        app = create_app()
        print("   Flask app: Created successfully")
        return True
        
    except Exception as e:
        print(f"❌ Web modules: Import error - {e}")
        return False

def main():
    """Run all tests"""
    print("🔍 macOS Authorization Discovery Tool - Setup Verification")
    print("=" * 60)
    
    tests = [
        ("Python Version", test_python_version),
        ("macOS Compatibility", test_macos_version),
        ("Dependencies", test_dependencies),
        ("Permissions", test_permissions),
        ("Core Modules", test_core_modules),
        ("Web Modules", test_web_modules)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n🧪 Testing {test_name}:")
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"❌ {test_name}: Error - {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    
    passed = sum(results)
    total = len(results)
    
    for i, (test_name, _) in enumerate(tests):
        status = "✅ PASS" if results[i] else "❌ FAIL"
        print(f"   {test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! The tool is ready to use.")
        print("\nNext steps:")
        print("   1. Run './setup.sh' if you haven't already")
        print("   2. Grant necessary permissions in System Preferences")
        print("   3. Start the application with './run.sh'")
        return 0
    elif passed >= total // 2:
        print("\n⚠️  Some tests failed, but basic functionality should work.")
        print("   Check the failed tests and grant necessary permissions.")
        return 0
    else:
        print("\n❌ Multiple critical tests failed. Please check your setup.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
