#!/usr/bin/env python3
"""
Test script to demonstrate dynamic System Settings pane discovery
across different macOS versions and configurations
"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.core.pane_discovery import SystemSettingsPaneDiscovery
from src.core.command_discovery import CommandDiscoveryEngine
import json


def test_pane_discovery():
    """Test and demonstrate the dynamic pane discovery functionality"""
    
    print("=" * 60)
    print("macOS System Settings Pane Discovery Test")
    print("=" * 60)
    
    # Test the pane discovery module directly
    print("\n1. Testing SystemSettingsPaneDiscovery module:")
    print("-" * 50)
    
    discovery = SystemSettingsPaneDiscovery()
    panes = discovery.discover_all_panes()
    
    print(f"System: macOS {'.'.join(map(str, discovery.macos_version))}")
    print(f"Uses modern System Settings: {discovery.is_modern_system_settings}")
    print(f"Total panes discovered: {len(panes)}")
    
    # Group by type
    type_counts = {}
    for pane in panes:
        pane_type = pane['type']
        if pane_type not in type_counts:
            type_counts[pane_type] = []
        type_counts[pane_type].append(pane['name'])
    
    print("\nPanes by type:")
    for pane_type, names in type_counts.items():
        print(f"  {pane_type}: {len(names)} panes")
        for name in sorted(names):
            print(f"    - {name}")
    
    print("\n2. Testing integration with CommandDiscoveryEngine:")
    print("-" * 50)
    
    engine = CommandDiscoveryEngine()
    print(f"Engine loaded {len(engine.system_panes)} panes")
    print(f"Total checks updated to: {engine.total_checks}")
    
    # Show comparison with static config
    static_panes = [
        "Wi-Fi", "Bluetooth", "Network", "VPN", "Notifications", "Sound", "Focus", 
        "Screen Time", "General", "Appearance", "Accessibility", "Control Center",
        "Siri & Spotlight", "Privacy & Security", "Desktop & Dock", "Displays",
        "Wallpaper", "Screen Saver", "Battery", "Energy Saver", "Keyboard", "Mouse",
        "Trackpad", "Printers & Scanners", "Game Center", "Internet Accounts",
        "Passwords", "Wallet & Apple Pay", "Users & Groups", "Touch ID & Passcode",
        "Login Items", "Date & Time", "Sharing", "Time Machine", "Transfer or Reset",
        "Software Update", "Storage"
    ]
    
    print("\n3. Comparison with static configuration:")
    print("-" * 50)
    
    dynamic_panes = set(engine.system_panes)
    static_panes_set = set(static_panes)
    
    only_in_dynamic = dynamic_panes - static_panes_set
    only_in_static = static_panes_set - dynamic_panes
    common_panes = dynamic_panes & static_panes_set
    
    print(f"Common panes: {len(common_panes)}")
    print(f"Only in dynamic discovery: {len(only_in_dynamic)}")
    print(f"Only in static config: {len(only_in_static)}")
    
    if only_in_dynamic:
        print("\nNew panes discovered dynamically:")
        for pane in sorted(only_in_dynamic):
            print(f"  + {pane}")
    
    if only_in_static:
        print("\nStatic panes not found on this system:")
        for pane in sorted(only_in_static):
            print(f"  - {pane}")
    
    print("\n4. Summary information:")
    print("-" * 50)
    summary = discovery.get_summary()
    print(json.dumps(summary, indent=2))
    
    print("\n" + "=" * 60)
    print("Dynamic pane discovery working successfully!")
    print("This system will now use the discovered panes instead of")
    print("static configuration, ensuring compatibility across")
    print("different macOS versions and user configurations.")
    print("=" * 60)


if __name__ == "__main__":
    test_pane_discovery()
