#!/usr/bin/env python3
"""
Test element detection in a specific System Settings pane
"""

import sys
import time
import subprocess
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

try:
    from core.discovery_engine import SystemSettingsNavigator
    from core.hardware_profile import HardwareProfileManager
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

def test_element_detection(pane_name="Privacy & Security"):
    """Test element detection for a specific pane"""
    
    print(f"🔍 Testing element detection for: {pane_name}")
    print("=" * 50)
    
    # Initialize components
    hardware_manager = HardwareProfileManager()
    navigator = SystemSettingsNavigator(hardware_manager)
    
    try:
        # Navigate to the pane
        print(f"📍 Navigating to {pane_name}...")
        if navigator.navigate_to_pane(pane_name):
            print(f"✅ Successfully navigated to {pane_name}")
            
            # Wait a bit for the pane to load
            print("⏳ Waiting for pane to load...")
            time.sleep(3)
            
            # Get clickable elements
            print("🔍 Detecting clickable elements...")
            elements = navigator.get_clickable_elements()
            
            print(f"\n📊 Results:")
            print(f"Found {len(elements)} clickable elements")
            
            if elements:
                print("\n🎯 Clickable elements detected:")
                for i, element in enumerate(elements[:10], 1):  # Show first 10
                    print(f"  {i:2d}. {element['name']} ({element['type']})")
                
                if len(elements) > 10:
                    print(f"  ... and {len(elements) - 10} more elements")
                
                # Test clicking the first element
                if elements:
                    first_element = elements[0]
                    print(f"\n🖱️  Testing click on: {first_element['name']}")
                    
                    if navigator.click_element(first_element['name']):
                        print("✅ Click successful")
                        time.sleep(2)  # Wait to see any dialogs/changes
                    else:
                        print("❌ Click failed")
            else:
                print("❌ No clickable elements found")
                
                # Try the fallback method explicitly
                print("\n🔄 Trying fallback detection method...")
                fallback_elements = navigator._get_elements_fallback()
                
                if fallback_elements:
                    print(f"✅ Fallback found {len(fallback_elements)} elements:")
                    for element in fallback_elements[:5]:
                        print(f"  - {element['name']} ({element['type']})")
                else:
                    print("❌ Fallback method also found no elements")
        else:
            print(f"❌ Failed to navigate to {pane_name}")
            
    except Exception as e:
        print(f"❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 50)
    print("Test completed")

if __name__ == "__main__":
    pane = sys.argv[1] if len(sys.argv) > 1 else "Privacy & Security"
    test_element_detection(pane)
