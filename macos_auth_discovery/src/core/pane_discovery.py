#!/usr/bin/env python3
"""
Dynamic System Settings Pane Discovery
Discovers available System Settings panes dynamically based on current system and macOS version
"""

import logging
import subprocess
import os
import re
from typing import Dict, List, Set, Optional, Any, Union
from pathlib import Path


class SystemSettingsPaneDiscovery:
    """Dynamically discovers available System Settings panes and preference panes"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.discovered_panes = []
        self.macos_version = self._get_macos_version()
        self.is_modern_system_settings = self._is_modern_system_settings()
        
    def _get_macos_version(self) -> tuple:
        """Get macOS version as tuple (major, minor, patch)"""
        try:
            result = subprocess.run(
                ['sw_vers', '-productVersion'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            version_str = result.stdout.strip()
            parts = version_str.split('.')
            return tuple(int(p) for p in parts[:3])
        except Exception as e:
            self.logger.warning(f"Failed to get macOS version: {e}")
            return (15, 0, 0)  # Default to recent version
    
    def _is_modern_system_settings(self) -> bool:
        """Check if running macOS 13+ with modern System Settings app"""
        major_version = self.macos_version[0]
        return major_version >= 13
    
    def _run_command(self, command: List[str]) -> Optional[str]:
        """Run a command and return output, or None on failure"""
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=True,
                timeout=10
            )
            return result.stdout.strip()
        except Exception as e:
            self.logger.debug(f"Command failed {' '.join(command)}: {e}")
            return None
    
    def _discover_modern_system_settings_panes(self) -> List[Dict[str, Union[str, bool]]]:
        """Discover panes for modern System Settings app (macOS 13+)"""
        panes = []
        
        # Check System Settings Sidebar.plist for available extensions
        sidebar_plist = "/System/Applications/System Settings.app/Contents/Resources/Sidebar.plist"
        if os.path.exists(sidebar_plist):
            try:
                output = self._run_command(['plutil', '-p', sidebar_plist])
                if output:
                    # Extract extension identifiers
                    extension_pattern = r'"(com\.apple\.[^"]+)"'
                    extensions = re.findall(extension_pattern, output)
                    
                    for ext_id in extensions:
                        # Convert extension ID to human-readable name
                        pane_name = self._extension_id_to_name(ext_id)
                        if pane_name:
                            panes.append({
                                'name': pane_name,
                                'identifier': ext_id,
                                'type': 'system_settings_extension',
                                'available': True
                            })
            except Exception as e:
                self.logger.warning(f"Failed to parse Sidebar.plist: {e}")
        
        # Add built-in panes that might not be in Sidebar.plist
        builtin_panes = [
            {'name': 'General', 'identifier': 'com.apple.systempreferences.GeneralSettings', 'type': 'builtin'},
            {'name': 'Software Update', 'identifier': 'com.apple.preferences.softwareupdate', 'type': 'builtin'},
            {'name': 'Storage', 'identifier': 'com.apple.preferences.storage', 'type': 'builtin'},
            {'name': 'Time Machine', 'identifier': 'com.apple.preferences.TimeMachineSettings', 'type': 'builtin'},
            {'name': 'Sharing', 'identifier': 'com.apple.preferences.sharing', 'type': 'builtin'},
            {'name': 'Date & Time', 'identifier': 'com.apple.preferences.datetime', 'type': 'builtin'},
            {'name': 'Energy Saver', 'identifier': 'com.apple.preferences.energysaver', 'type': 'builtin'},
            {'name': 'Startup Disk', 'identifier': 'com.apple.preferences.startupdisk', 'type': 'builtin'},
        ]
        
        for pane in builtin_panes:
            if not any(p['name'] == pane['name'] for p in panes):
                pane_copy = pane.copy()
                pane_copy['available'] = True
                panes.append(pane_copy)
        
        return panes
    
    def _discover_legacy_preference_panes(self) -> List[Dict[str, Union[str, bool]]]:
        """Discover panes for legacy System Preferences app (macOS 12 and earlier)"""
        panes = []
        
        # Check /System/Library/PreferencePanes/
        system_pref_dir = "/System/Library/PreferencePanes"
        if os.path.exists(system_pref_dir):
            try:
                pref_panes = os.listdir(system_pref_dir)
                for pane_bundle in pref_panes:
                    if pane_bundle.endswith('.prefPane'):
                        pane_name = pane_bundle.replace('.prefPane', '')
                        # Convert technical name to user-friendly name
                        friendly_name = self._prefpane_name_to_friendly(pane_name)
                        panes.append({
                            'name': friendly_name,
                            'identifier': pane_name,
                            'type': 'preference_pane',
                            'available': True,
                            'path': os.path.join(system_pref_dir, pane_bundle)
                        })
            except Exception as e:
                self.logger.warning(f"Failed to discover preference panes: {e}")
        
        # Check user-installed preference panes
        user_pref_dir = os.path.expanduser("~/Library/PreferencePanes")
        if os.path.exists(user_pref_dir):
            try:
                user_panes = os.listdir(user_pref_dir)
                for pane_bundle in user_panes:
                    if pane_bundle.endswith('.prefPane'):
                        pane_name = pane_bundle.replace('.prefPane', '')
                        friendly_name = self._prefpane_name_to_friendly(pane_name)
                        panes.append({
                            'name': friendly_name,
                            'identifier': pane_name,
                            'type': 'user_preference_pane',
                            'available': True,
                            'path': os.path.join(user_pref_dir, pane_bundle)
                        })
            except Exception as e:
                self.logger.warning(f"Failed to discover user preference panes: {e}")
        
        return panes
    
    def _extension_id_to_name(self, extension_id: str) -> Optional[str]:
        """Convert System Settings extension ID to human-readable name"""
        name_mapping = {
            'com.apple.systempreferences.AppleIDSettings': 'Apple ID',
            'com.apple.Family-Settings.extension': 'Family',
            'com.apple.FollowUpSettings.FollowUpSettingsExtension': 'Follow Up',
            'com.apple.wifi-settings-extension': 'Wi-Fi',
            'com.apple.BluetoothSettings': 'Bluetooth',
            'com.apple.Network-Settings.extension': 'Network',
            'com.apple.NetworkExtensionSettingsUI.NESettingsUIExtension': 'VPN',
            'com.apple.ClassroomSettings': 'Classroom',
            'com.apple.Classroom-Settings.extension': 'Classroom Settings',
            'com.apple.Notifications-Settings.extension': 'Notifications',
            'com.apple.Sound-Settings.extension': 'Sound',
            'com.apple.Focus-Settings.extension': 'Focus',
            'com.apple.Screen-Time-Settings.extension': 'Screen Time',
            'com.apple.systempreferences.GeneralSettings': 'General',
            'com.apple.Appearance-Settings.extension': 'Appearance',
            'com.apple.Accessibility-Settings.extension': 'Accessibility',
            'com.apple.ControlCenter-Settings.extension': 'Control Center',
            'com.apple.Siri-Settings.extension': 'Siri & Spotlight',
            'com.apple.settings.PrivacySecurity.extension': 'Privacy & Security',
            'com.apple.Desktop-Settings.extension': 'Desktop & Dock',
            'com.apple.Displays-Settings.extension': 'Displays',
            'com.apple.Wallpaper-Settings.extension': 'Wallpaper',
            'com.apple.ScreenSaver-Settings.extension': 'Screen Saver',
            'com.apple.Battery-Settings.extension': 'Battery',
            'com.apple.Keyboard-Settings.extension': 'Keyboard',
            'com.apple.Mouse-Settings.extension': 'Mouse',
            'com.apple.Trackpad-Settings.extension': 'Trackpad',
            'com.apple.Print-Scan-Settings.extension': 'Printers & Scanners',
            'com.apple.Game-Center-Settings.extension': 'Game Center',
            'com.apple.Game-Controller-Settings.extension': 'Game Controller',
            'com.apple.Internet-Accounts-Settings.extension': 'Internet Accounts',
            'com.apple.Passwords': 'Passwords',
            'com.apple.Passwords-Settings.extension': 'Passwords',
            'com.apple.WalletSettingsExtension': 'Wallet & Apple Pay',
            'com.apple.Users-Groups-Settings.extension': 'Users & Groups',
            'com.apple.Touch-ID-Settings.extension': 'Touch ID & Passcode',
            'com.apple.Lock-Screen-Settings.extension': 'Lock Screen',
            'com.apple.HeadphoneSettings': 'Headphones',
            'com.apple.CD-DVD-Settings.extension': 'CDs & DVDs',
            'com.apple.Spotlight-Settings.extension': 'Spotlight',
        }
        
        return name_mapping.get(extension_id)
    
    def _prefpane_name_to_friendly(self, prefpane_name: str) -> str:
        """Convert preference pane technical name to user-friendly name"""
        name_mapping = {
            'Accounts': 'Internet Accounts',
            'Appearance': 'Appearance', 
            'AppleIDPrefPane': 'Apple ID',
            'Battery': 'Battery',
            'Bluetooth': 'Bluetooth',
            'ClassKitPreferencePane': 'ClassKit',
            'ClassroomSettings': 'Classroom',
            'DateAndTime': 'Date & Time',
            'DesktopScreenEffectsPref': 'Desktop & Screen Saver',
            'DigiHubDiscs': 'CDs & DVDs',
            'Displays': 'Displays',
            'Dock': 'Dock',
            'EnergySaver': 'Energy Saver',
            'EnergySaverPref': 'Energy Saver',
            'Expose': 'Mission Control',
            'Extensions': 'Extensions',
            'FamilySharingPrefPane': 'Family',
            'InternetAccounts': 'Internet Accounts',
            'Keyboard': 'Keyboard',
            'Localization': 'Language & Region',
            'Mouse': 'Mouse',
            'Network': 'Network',
            'Notifications': 'Notifications',
            'Passwords': 'Passwords',
            'PrintAndFax': 'Printers & Scanners',
            'PrintAndScan': 'Printers & Scanners',
            'Profiles': 'Profiles',
            'ScreenTime': 'Screen Time',
            'Security': 'Security & Privacy',
            'SharingPref': 'Sharing',
            'SoftwareUpdate': 'Software Update',
            'Sound': 'Sound',
            'Speech': 'Speech',
            'Spotlight': 'Spotlight',
            'StartupDisk': 'Startup Disk',
            'TimeMachine': 'Time Machine',
            'TouchID': 'Touch ID',
            'Trackpad': 'Trackpad',
            'UniversalAccessPref': 'Accessibility',
            'Wallet': 'Wallet & Apple Pay',
        }
        
        return name_mapping.get(prefpane_name, prefpane_name)
    
    def _check_pane_availability(self, pane: Dict[str, Union[str, bool]]) -> bool:
        """Check if a specific pane is actually available on this system"""
        try:
            # For System Settings extensions, check if the extension exists
            if pane['type'] == 'system_settings_extension':
                # Check if System Settings can open this pane
                # Note: This is a basic availability check
                return True  # Most extensions should be available
            
            # For preference panes, check if the file exists
            elif pane['type'] in ['preference_pane', 'user_preference_pane']:
                return os.path.exists(pane.get('path', ''))
            
            # For builtin panes, assume they're available
            return True
            
        except Exception as e:
            self.logger.debug(f"Failed to check availability for {pane['name']}: {e}")
            return False
    
    def discover_all_panes(self) -> List[Dict[str, Union[str, bool]]]:
        """Discover all available System Settings/Preferences panes on this system"""
        self.logger.info(f"Discovering System Settings panes for macOS {'.'.join(map(str, self.macos_version))}")
        
        all_panes = []
        
        if self.is_modern_system_settings:
            self.logger.info("Using modern System Settings discovery")
            all_panes.extend(self._discover_modern_system_settings_panes())
        else:
            self.logger.info("Using legacy System Preferences discovery")
            all_panes.extend(self._discover_legacy_preference_panes())
        
        # Verify availability and remove duplicates
        verified_panes = []
        seen_names = set()
        
        for pane in all_panes:
            # Check availability
            pane['available'] = self._check_pane_availability(pane)
            
            # Remove duplicates (prefer system extensions over others)
            if pane['name'] not in seen_names:
                verified_panes.append(pane)
                seen_names.add(pane['name'])
        
        # Sort by name for consistent ordering
        verified_panes.sort(key=lambda x: x['name'])
        
        self.discovered_panes = verified_panes
        self.logger.info(f"Discovered {len(verified_panes)} System Settings panes")
        
        return verified_panes
    
    def get_pane_names(self) -> List[str]:
        """Get list of pane names only"""
        if not self.discovered_panes:
            self.discover_all_panes()
        
        return [pane['name'] for pane in self.discovered_panes if pane['available']]
    
    def get_pane_identifiers(self) -> List[str]:
        """Get list of pane identifiers only"""
        if not self.discovered_panes:
            self.discover_all_panes()
        
        return [pane['identifier'] for pane in self.discovered_panes if pane['available']]
    
    def get_panes_by_type(self, pane_type: str) -> List[Dict[str, Union[str, bool]]]:
        """Get panes filtered by type"""
        if not self.discovered_panes:
            self.discover_all_panes()
        
        return [pane for pane in self.discovered_panes 
                if pane['type'] == pane_type and pane['available']]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of discovered panes"""
        if not self.discovered_panes:
            self.discover_all_panes()
        
        available_panes = [p for p in self.discovered_panes if p['available']]
        types = {}
        for pane in available_panes:
            pane_type = pane['type']
            if pane_type not in types:
                types[pane_type] = 0
            types[pane_type] += 1
        
        return {
            'total_panes': len(available_panes),
            'macos_version': '.'.join(map(str, self.macos_version)),
            'uses_modern_settings': self.is_modern_system_settings,
            'pane_types': types,
            'pane_names': [p['name'] for p in available_panes]
        }
