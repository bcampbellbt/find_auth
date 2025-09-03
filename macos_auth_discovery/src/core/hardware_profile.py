#!/usr/bin/env python3
"""
Hardware Profile Manager
Handles hardware detection and classification for System Settings navigation
"""

import subprocess
import logging
import json
from typing import Dict, List, Optional

try:
    import objc
    from Foundation import NSProcessInfo
    from IOKit import *
    HAS_OBJC = True
except ImportError:
    HAS_OBJC = False

class HardwareProfileManager:
    """Manages hardware detection and classification for macOS systems"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hardware_profile = {}
        self.unavailable_features = []
        self._detect_hardware()
    
    def _detect_hardware(self):
        """Detect current hardware configuration"""
        try:
            self.hardware_profile = {
                'model': self._get_model_identifier(),
                'processor': self._get_processor_info(),
                'has_battery': self._has_battery(),
                'has_touch_id': self._has_touch_id(),
                'has_face_id': self._has_face_id(),
                'has_thunderbolt': self._has_thunderbolt(),
                'has_ethernet': self._has_ethernet(),
                'has_wifi': self._has_wifi(),
                'has_bluetooth': self._has_bluetooth(),
                'display_count': self._get_display_count(),
                'audio_devices': self._get_audio_devices(),
                'macos_version': self._get_macos_version()
            }
            
            self.logger.info(f"Hardware profile detected: {self.hardware_profile['model']}")
            
        except Exception as e:
            self.logger.error(f"Error detecting hardware: {e}")
            self.hardware_profile = self._get_fallback_profile()
    
    def _get_model_identifier(self) -> str:
        """Get Mac model identifier"""
        try:
            result = subprocess.run(['sysctl', '-n', 'hw.model'], 
                                  capture_output=True, text=True)
            return result.stdout.strip()
        except Exception:
            return "Unknown"
    
    def _get_processor_info(self) -> Dict[str, str]:
        """Get processor information"""
        try:
            # Get processor brand
            brand_result = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], 
                                        capture_output=True, text=True)
            
            # Determine architecture
            arch_result = subprocess.run(['uname', '-m'], 
                                       capture_output=True, text=True)
            
            return {
                'brand': brand_result.stdout.strip(),
                'architecture': arch_result.stdout.strip(),
                'is_apple_silicon': arch_result.stdout.strip() == 'arm64'
            }
        except Exception:
            return {'brand': 'Unknown', 'architecture': 'Unknown', 'is_apple_silicon': False}
    
    def _has_battery(self) -> bool:
        """Check if system has a battery"""
        try:
            result = subprocess.run(['pmset', '-g', 'batt'], 
                                  capture_output=True, text=True)
            return 'InternalBattery' in result.stdout
        except Exception:
            return False
    
    def _has_touch_id(self) -> bool:
        """Check if system has Touch ID"""
        try:
            # Check for Touch ID capability
            result = subprocess.run(['bioutil', '-r'], 
                                  capture_output=True, text=True)
            return 'Touch ID' in result.stdout or result.returncode == 0
        except Exception:
            return False
    
    def _has_face_id(self) -> bool:
        """Check if system has Face ID (future-proofing)"""
        # Currently no Macs have Face ID, but keeping for future
        return False
    
    def _has_thunderbolt(self) -> bool:
        """Check if system has Thunderbolt ports"""
        try:
            result = subprocess.run(['system_profiler', 'SPThunderboltDataType', '-json'], 
                                  capture_output=True, text=True)
            data = json.loads(result.stdout)
            return len(data.get('SPThunderboltDataType', [])) > 0
        except Exception:
            return False
    
    def _has_ethernet(self) -> bool:
        """Check if system has Ethernet"""
        try:
            result = subprocess.run(['networksetup', '-listallhardwareports'], 
                                  capture_output=True, text=True)
            return 'Ethernet' in result.stdout
        except Exception:
            return False
    
    def _has_wifi(self) -> bool:
        """Check if system has Wi-Fi"""
        try:
            result = subprocess.run(['networksetup', '-listallhardwareports'], 
                                  capture_output=True, text=True)
            return 'Wi-Fi' in result.stdout
        except Exception:
            return True  # Assume Wi-Fi is present on most modern Macs
    
    def _has_bluetooth(self) -> bool:
        """Check if system has Bluetooth"""
        try:
            result = subprocess.run(['system_profiler', 'SPBluetoothDataType', '-json'], 
                                  capture_output=True, text=True)
            data = json.loads(result.stdout)
            return len(data.get('SPBluetoothDataType', [])) > 0
        except Exception:
            return True  # Assume Bluetooth is present on most modern Macs
    
    def _get_display_count(self) -> int:
        """Get number of displays"""
        try:
            result = subprocess.run(['system_profiler', 'SPDisplaysDataType', '-json'], 
                                  capture_output=True, text=True)
            data = json.loads(result.stdout)
            displays = data.get('SPDisplaysDataType', [])
            return len(displays)
        except Exception:
            return 1  # Assume at least one display
    
    def _get_audio_devices(self) -> List[str]:
        """Get audio device information"""
        try:
            result = subprocess.run(['system_profiler', 'SPAudioDataType', '-json'], 
                                  capture_output=True, text=True)
            data = json.loads(result.stdout)
            audio_data = data.get('SPAudioDataType', [])
            devices = []
            for item in audio_data:
                if '_items' in item:
                    for device in item['_items']:
                        devices.append(device.get('_name', 'Unknown'))
            return devices
        except Exception:
            return []
    
    def _get_macos_version(self) -> Dict[str, str]:
        """Get macOS version information"""
        try:
            result = subprocess.run(['sw_vers'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            version_info = {}
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    version_info[key.strip()] = value.strip()
            return version_info
        except Exception:
            return {'ProductName': 'macOS', 'ProductVersion': 'Unknown'}
    
    def _get_fallback_profile(self) -> Dict:
        """Get fallback hardware profile when detection fails"""
        return {
            'model': 'Unknown',
            'processor': {'brand': 'Unknown', 'architecture': 'Unknown', 'is_apple_silicon': False},
            'has_battery': False,
            'has_touch_id': False,
            'has_face_id': False,
            'has_thunderbolt': False,
            'has_ethernet': True,
            'has_wifi': True,
            'has_bluetooth': True,
            'display_count': 1,
            'audio_devices': [],
            'macos_version': {'ProductName': 'macOS', 'ProductVersion': 'Unknown'}
        }
    
    def is_feature_available(self, feature: str) -> bool:
        """Check if a hardware feature is available"""
        return self.hardware_profile.get(feature, False)
    
    def get_unavailable_features(self) -> List[str]:
        """Get list of unavailable hardware features"""
        return self.unavailable_features
    
    def add_unavailable_feature(self, feature: str, reason: str = ""):
        """Add a feature to the unavailable list"""
        feature_entry = f"{feature}: {reason}" if reason else feature
        if feature_entry not in self.unavailable_features:
            self.unavailable_features.append(feature_entry)
            self.logger.info(f"Added unavailable feature: {feature_entry}")
    
    def get_hardware_profile(self) -> Dict:
        """Get complete hardware profile"""
        return self.hardware_profile.copy()
    
    def should_skip_setting(self, setting_path: str) -> bool:
        """Determine if a setting should be skipped based on hardware"""
        # Hardware-specific settings that should be skipped if hardware not present
        hardware_dependent_settings = {
            'Battery': lambda: not self.is_feature_available('has_battery'),
            'Touch ID': lambda: not self.is_feature_available('has_touch_id'),
            'Face ID': lambda: not self.is_feature_available('has_face_id'),
            'Thunderbolt': lambda: not self.is_feature_available('has_thunderbolt'),
            'Ethernet': lambda: not self.is_feature_available('has_ethernet'),
        }
        
        for hardware_feature, check_func in hardware_dependent_settings.items():
            if hardware_feature.lower() in setting_path.lower() and check_func():
                self.add_unavailable_feature(
                    f"System Settings: {setting_path}",
                    f"Hardware not present: {hardware_feature}"
                )
                return True
        
        return False
