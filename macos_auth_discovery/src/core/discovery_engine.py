#!/usr/bin/env python3
"""
Authorization Discovery Engine
Core component that navigates System Settings and detects authorization requests
"""

import logging
import time
import subprocess
import threading
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

try:
    import objc
    from AppKit import *
    from ApplicationServices import *
    from Accessibility import *
    HAS_APPKIT = True
except ImportError:
    HAS_APPKIT = False

from .system_monitor import SystemLevelMonitor, AuthorizationEvent
from .hardware_profile import HardwareProfileManager

class SystemSettingsNavigator:
    """Handles navigation through macOS System Settings"""
    
    def __init__(self, hardware_manager: HardwareProfileManager):
        self.logger = logging.getLogger(__name__)
        self.hardware_manager = hardware_manager
        self.visited_paths = []
        self.current_path = ""
        
    def open_system_settings(self) -> bool:
        """Open System Settings application"""
        try:
            # First check if we have accessibility permissions
            if not self._check_accessibility_permissions():
                self.logger.error("Accessibility permissions required. Please grant Terminal/iTerm accessibility access in System Preferences > Privacy & Security > Accessibility")
                return False
            
            # Use AppleScript to open System Settings
            script = '''
            tell application "System Settings"
                activate
                delay 2
            end tell
            '''
            
            result = subprocess.run(['osascript', '-e', script], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info("System Settings opened successfully")
                return True
            else:
                self.logger.error(f"Failed to open System Settings: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error opening System Settings: {e}")
            return False
    
    def _check_accessibility_permissions(self) -> bool:
        """Check if the application has accessibility permissions"""
        try:
            # Try a simple accessibility check
            script = '''
            tell application "System Events"
                set processNames to name of every process
                return "Finder" is in processNames
            end tell
            '''
            
            result = subprocess.run(['osascript', '-e', script], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return True
            elif "assistive access" in result.stderr.lower():
                return False
            else:
                # Unknown error, assume we don't have permissions
                return False
                
        except Exception as e:
            self.logger.debug(f"Accessibility check error: {e}")
            return False
    
    def get_available_panes(self) -> List[str]:
        """Get list of available System Settings panes"""
        panes = [
            "Wi-Fi", "Bluetooth", "Network", "VPN", "Notifications", "Sound",
            "Focus", "Screen Time", "General", "Appearance", "Accessibility",
            "Control Center", "Siri & Spotlight", "Privacy & Security", 
            "Desktop & Dock", "Displays", "Wallpaper", "Screen Saver",
            "Battery", "Energy Saver", "Keyboard", "Mouse", "Trackpad",
            "Printers & Scanners", "Game Center", "Internet Accounts",
            "Passwords", "Wallet & Apple Pay", "Users & Groups",
            "Touch ID & Passcode", "Login Items", "Date & Time", "Sharing",
            "Time Machine", "Transfer or Reset", "Software Update", "Storage"
        ]
        
        # Filter based on hardware availability
        available_panes = []
        for pane in panes:
            if not self.hardware_manager.should_skip_setting(pane):
                available_panes.append(pane)
            else:
                self.logger.info(f"Skipping pane {pane} - hardware not available")
        
        return available_panes
    
    def navigate_to_pane(self, pane_name: str) -> bool:
        """Navigate to a specific System Settings pane"""
        try:
            # Use the correct URL schemes for macOS Sequoia
            url_mappings = {
                "Wi-Fi": "x-apple.systempreferences:com.apple.WiFi-Settings.extension",
                "Bluetooth": "x-apple.systempreferences:com.apple.BluetoothSettings",
                "General": "x-apple.systempreferences:com.apple.General-Settings.extension",
                "Privacy & Security": "x-apple.systempreferences:com.apple.PrivacySecurity-Settings.extension",
                "Displays": "x-apple.systempreferences:com.apple.Displays-Settings.extension",
                "Sound": "x-apple.systempreferences:com.apple.Sound-Settings.extension",
                "Keyboard": "x-apple.systempreferences:com.apple.Keyboard-Settings.extension",
                "Mouse": "x-apple.systempreferences:com.apple.Mouse-Settings.extension",
                "Trackpad": "x-apple.systempreferences:com.apple.Trackpad-Settings.extension",
                "Network": "x-apple.systempreferences:com.apple.Network-Settings.extension",
                "Notifications": "x-apple.systempreferences:com.apple.Notifications-Settings.extension",
                "Desktop & Dock": "x-apple.systempreferences:com.apple.Desktop-Settings.extension",
                "Accessibility": "x-apple.systempreferences:com.apple.Accessibility-Settings.extension",
                "Users & Groups": "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension",
                "Date & Time": "x-apple.systempreferences:com.apple.Date-Time-Settings.extension",
                "Sharing": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
                "Time Machine": "x-apple.systempreferences:com.apple.TimeMachine-Settings.extension",
                "Software Update": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
                "Battery": "x-apple.systempreferences:com.apple.Battery-Settings.extension",
                "Control Center": "x-apple.systempreferences:com.apple.ControlCenter-Settings.extension",
                "Siri & Spotlight": "x-apple.systempreferences:com.apple.Siri-Settings.extension",
                "Appearance": "x-apple.systempreferences:com.apple.Appearance-Settings.extension",
                "Focus": "x-apple.systempreferences:com.apple.Focus-Settings.extension",
                "Screen Time": "x-apple.systempreferences:com.apple.ScreenTime-Settings.extension",
                "Wallpaper": "x-apple.systempreferences:com.apple.Wallpaper-Settings.extension",
                "Screen Saver": "x-apple.systempreferences:com.apple.ScreenSaver-Settings.extension",
                "Energy Saver": "x-apple.systempreferences:com.apple.EnergySaver-Settings.extension",
                "Printers & Scanners": "x-apple.systempreferences:com.apple.Print-Scan-Settings.extension",
                "Game Center": "x-apple.systempreferences:com.apple.GameCenter-Settings.extension",
                "Internet Accounts": "x-apple.systempreferences:com.apple.Internet-Accounts-Settings.extension",
                "Passwords": "x-apple.systempreferences:com.apple.Passwords-Settings.extension",
                "Wallet & Apple Pay": "x-apple.systempreferences:com.apple.WalletSettingsExtension",
                "Touch ID & Passcode": "x-apple.systempreferences:com.apple.TouchID-Settings.extension",
                "Login Items": "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
                "Transfer or Reset": "x-apple.systempreferences:com.apple.Transfer-Reset-Settings.extension",
                "Storage": "x-apple.systempreferences:com.apple.Storage-Settings.extension"
            }
            
            url = url_mappings.get(pane_name)
            if url:
                # Try URL scheme navigation
                result = subprocess.run(['open', url], 
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.current_path = pane_name
                    self.logger.info(f"Navigated to pane via URL scheme: {pane_name}")
                    time.sleep(2)  # Wait for pane to load
                    return True
                else:
                    self.logger.warning(f"URL scheme failed for {pane_name}: {result.stderr}")
            
            # Fallback: just open System Settings and continue
            # This allows the discovery to continue even if specific navigation fails
            subprocess.run(['open', '-b', 'com.apple.systempreferences'], 
                          capture_output=True, text=True)
            
            self.current_path = pane_name
            self.logger.info(f"Using fallback navigation for pane: {pane_name}")
            time.sleep(1)
            return True  # Return True to allow discovery to continue
                
        except Exception as e:
            self.logger.error(f"Error navigating to pane {pane_name}: {e}")
            # Even on error, return True to allow discovery to continue
            self.current_path = pane_name
            return True
    
    def _fallback_navigate_to_pane(self, pane_name: str) -> bool:
        """Fallback navigation method using search"""
        try:
            # Try using search functionality in System Settings
            script = f'''
            tell application "System Settings"
                activate
                delay 2
            end tell
            
            tell application "System Events"
                tell process "System Settings"
                    -- Try to use the search field
                    try
                        keystroke "f" using command down
                        delay 0.5
                        keystroke "{pane_name}"
                        delay 1
                        keystroke return
                        delay 2
                        return true
                    on error errMsg
                        -- If search fails, try clicking in sidebar
                        try
                            set paneNames to {{"Wi-Fi", "WiFi"}}, {{"Bluetooth", "Bluetooth"}}, {{"Privacy & Security", "Privacy"}}, {{"General", "General"}}, {{"Displays", "Displays"}}, {{"Sound", "Sound"}}, {{"Keyboard", "Keyboard"}}, {{"Mouse", "Mouse"}}, {{"Trackpad", "Trackpad"}}
                            
                            repeat with pairItem in paneNames
                                set paneName to item 1 of pairItem
                                set displayName to item 2 of pairItem
                                if paneName is equal to "{pane_name}" then
                                    click button displayName of scroll area 1 of group 1 of splitter group 1 of group 1 of window 1
                                    delay 2
                                    return true
                                end if
                            end repeat
                            
                            return false
                        on error
                            return false
                        end try
                    end try
                end tell
            end tell
            '''
            
            result = subprocess.run(['osascript', '-e', script], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0 and "true" in result.stdout:
                self.current_path = pane_name
                self.logger.info(f"Navigated to pane via search: {pane_name}")
                return True
            else:
                self.logger.warning(f"Failed to navigate to pane: {pane_name}")
                # Try one more approach - direct URL opening
                return self._try_direct_url_navigation(pane_name)
                
        except Exception as e:
            self.logger.error(f"Fallback navigation error for {pane_name}: {e}")
            return False
    
    def _try_direct_url_navigation(self, pane_name: str) -> bool:
        """Try direct URL navigation as last resort"""
        try:
            # Simple mapping for common panes
            simple_urls = {
                "Wi-Fi": "x-apple.systempreferences:wifi",
                "Bluetooth": "x-apple.systempreferences:bluetooth", 
                "General": "x-apple.systempreferences:general",
                "Privacy & Security": "x-apple.systempreferences:security",
                "Displays": "x-apple.systempreferences:displays",
                "Sound": "x-apple.systempreferences:sound",
                "Keyboard": "x-apple.systempreferences:keyboard",
                "Mouse": "x-apple.systempreferences:mouse",
                "Trackpad": "x-apple.systempreferences:trackpad"
            }
            
            url = simple_urls.get(pane_name)
            if url:
                subprocess.run(['open', url], capture_output=True)
                time.sleep(2)
                self.current_path = pane_name
                self.logger.info(f"Navigated to pane via direct URL: {pane_name}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Direct URL navigation failed for {pane_name}: {e}")
            return False
    
    def get_clickable_elements(self) -> List[Dict[str, str]]:
        """Get clickable elements in current pane"""
        elements = []
        
        try:
            # Use comprehensive AppleScript to recursively find all clickable elements
            script = '''
            on getElementsRecursively(elem, depth)
                set elementList to {}
                if depth > 10 then return elementList -- prevent infinite recursion
                
                try
                    set elemClass to class of elem as string
                    set elemName to ""
                    set elemTitle to ""
                    set elemHelp to ""
                    
                    try
                        set elemName to name of elem as string
                    end try
                    try
                        set elemTitle to title of elem as string
                    end try
                    try
                        set elemHelp to help of elem as string
                    end try
                    
                    -- Check if this element is clickable
                    if elemClass contains "button" or elemClass contains "checkbox" or elemClass contains "radio" or elemClass contains "pop up" or elemClass contains "menu" or elemClass contains "slider" or elemClass contains "stepper" or elemClass contains "text field" then
                        set elementText to ""
                        if elemName is not "" then
                            set elementText to elemName
                        else if elemTitle is not "" then
                            set elementText to elemTitle
                        else if elemHelp is not "" then
                            set elementText to elemHelp
                        else
                            set elementText to "Unnamed " & elemClass
                        end if
                        
                        if elementText is not "" and elementText is not "missing value" then
                            set end of elementList to elementText & "|" & elemClass
                        end if
                    end if
                    
                    -- Recursively check child elements
                    try
                        set childElements to every UI element of elem
                        repeat with childElem in childElements
                            set childList to my getElementsRecursively(childElem, depth + 1)
                            set elementList to elementList & childList
                        end repeat
                    end try
                    
                end try
                
                return elementList
            end getElementsRecursively
            
            tell application "System Events"
                tell process "System Settings"
                    try
                        set frontWin to front window
                        set allElements to my getElementsRecursively(frontWin, 0)
                        return allElements
                    on error errMsg
                        return {"Error: " & errMsg}
                    end try
                end tell
            end tell
            '''
            
            result = subprocess.run(['osascript', '-e', script], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                seen_elements = set()  # Avoid duplicates
                
                for line in lines:
                    line = line.strip()
                    if '|' in line and not line.startswith('Error:'):
                        try:
                            name, elem_type = line.split('|', 1)
                            name = name.strip()
                            elem_type = elem_type.strip()
                            
                            # Filter out system elements we don't want to click
                            if name and name not in seen_elements and not any(skip in name.lower() for skip in [
                                'close', 'minimize', 'zoom', 'toolbar', 'window',
                                'scroll', 'splitter', 'system settings', 'back'
                            ]):
                                elements.append({
                                    'name': name,
                                    'type': elem_type,
                                    'path': f"{self.current_path} > {name}"
                                })
                                seen_elements.add(name)
                        except ValueError:
                            continue
            else:
                # Fallback: try a simpler approach
                self.logger.warning(f"Comprehensive element detection failed, trying fallback approach")
                elements = self._get_elements_fallback()
            
        except Exception as e:
            self.logger.error(f"Error getting clickable elements: {e}")
            # Try fallback approach
            elements = self._get_elements_fallback()
        
        self.logger.info(f"Found {len(elements)} clickable elements in {self.current_path}")
        if elements:
            self.logger.debug(f"Elements found: {[e['name'] for e in elements[:5]]}{'...' if len(elements) > 5 else ''}")
        
        return elements
    
    def _get_elements_fallback(self) -> List[Dict[str, str]]:
        """Fallback method for finding elements using simpler AppleScript"""
        elements = []
        try:
            # Try different element types one by one
            element_types = ['button', 'checkbox', 'radio button', 'pop up button', 'text field', 'slider']
            
            for elem_type in element_types:
                script = f'''
                tell application "System Events"
                    tell process "System Settings"
                        try
                            set elemList to every {elem_type} of front window
                            set results to {{}}
                            repeat with elem in elemList
                                try
                                    set elemName to name of elem as string
                                    if elemName is not "" and elemName is not "missing value" then
                                        set end of results to elemName & "|{elem_type}"
                                    end if
                                end try
                            end repeat
                            return results
                        on error
                            return {{}}
                        end try
                    end tell
                end tell
                '''
                
                result = subprocess.run(['osascript', '-e', script], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if '|' in line:
                            try:
                                name, elem_class = line.split('|', 1)
                                name = name.strip()
                                if name:
                                    elements.append({
                                        'name': name,
                                        'type': elem_class.strip(),
                                        'path': f"{self.current_path} > {name}"
                                    })
                            except ValueError:
                                continue
        
        except Exception as e:
            self.logger.error(f"Fallback element detection failed: {e}")
        
        return elements
    
    def click_element(self, element_name: str) -> bool:
        """Click on a specific UI element"""
        try:
            # Try multiple approaches to click the element
            click_scripts = [
                # Try as button first
                f'''
                tell application "System Events"
                    tell process "System Settings"
                        try
                            click button "{element_name}" of front window
                            delay 1
                            return "success"
                        end try
                    end tell
                end tell
                ''',
                # Try as checkbox
                f'''
                tell application "System Events"
                    tell process "System Settings"
                        try
                            click checkbox "{element_name}" of front window
                            delay 1
                            return "success"
                        end try
                    end tell
                end tell
                ''',
                # Try as radio button
                f'''
                tell application "System Events"
                    tell process "System Settings"
                        try
                            click radio button "{element_name}" of front window
                            delay 1
                            return "success"
                        end try
                    end tell
                end tell
                ''',
                # Try as pop up button
                f'''
                tell application "System Events"
                    tell process "System Settings"
                        try
                            click pop up button "{element_name}" of front window
                            delay 1
                            return "success"
                        end try
                    end tell
                end tell
                ''',
                # Try recursive search for the element
                f'''
                on clickElementRecursively(elem, targetName)
                    try
                        set elemName to name of elem as string
                        if elemName contains targetName then
                            click elem
                            return true
                        end if
                        
                        set childElements to every UI element of elem
                        repeat with childElem in childElements
                            if my clickElementRecursively(childElem, targetName) then
                                return true
                            end if
                        end repeat
                    end try
                    return false
                end clickElementRecursively
                
                tell application "System Events"
                    tell process "System Settings"
                        try
                            set frontWin to front window
                            if my clickElementRecursively(frontWin, "{element_name}") then
                                delay 1
                                return "success"
                            end if
                        end try
                    end tell
                end tell
                '''
            ]
            
            for script in click_scripts:
                result = subprocess.run(['osascript', '-e', script], 
                                      capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0 and "success" in result.stdout:
                    self.logger.info(f"Successfully clicked element: {element_name}")
                    self.visited_paths.append(f"{self.current_path} > {element_name}")
                    return True
            
            self.logger.warning(f"Failed to click element: {element_name}")
            return False
            
        except Exception as e:
            self.logger.error(f"Error clicking element {element_name}: {e}")
            return False


class AuthorizationDiscoveryEngine:
    """Main discovery engine that orchestrates the authorization discovery process"""
    
    def __init__(self, hardware_manager: HardwareProfileManager, 
                 system_monitor: SystemLevelMonitor):
        self.logger = logging.getLogger(__name__)
        self.hardware_manager = hardware_manager
        self.system_monitor = system_monitor
        self.navigator = SystemSettingsNavigator(hardware_manager)
        
        self.discovery_results = []
        self.is_running = False
        self.start_time = None
        self.progress = 0
        self.total_items = 0
        
        # Set up monitoring callback
        self.system_monitor.add_event_callback(self._on_authorization_event)
    
    def start_discovery(self):
        """Start the authorization discovery process"""
        if self.is_running:
            self.logger.warning("Discovery already running")
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        self.progress = 0
        self.discovery_results.clear()
        
        self.logger.info("Starting authorization discovery process")
        
        try:
            # Start system monitoring
            self.system_monitor.start_monitoring()
            
            # Open System Settings
            if not self.navigator.open_system_settings():
                raise Exception("Failed to open System Settings")
            
            # Get available panes
            panes = self.navigator.get_available_panes()
            self.total_items = len(panes)
            
            self.logger.info(f"Found {self.total_items} System Settings panes to explore")
            
            # Iterate through each pane
            for i, pane in enumerate(panes):
                if not self.is_running:  # Check for early termination
                    break
                
                self.logger.info(f"Exploring pane {i+1}/{self.total_items}: {pane}")
                self._explore_pane(pane)
                self.progress = int((i + 1) / self.total_items * 100)
                
                # Small delay between panes
                time.sleep(1)
            
            # Stop monitoring
            self.system_monitor.stop_monitoring()
            
            # Generate final report
            self._generate_discovery_report()
            
            self.logger.info("Authorization discovery completed successfully")
            
        except Exception as e:
            self.logger.error(f"Discovery error: {e}")
        finally:
            self.is_running = False
            self.system_monitor.stop_monitoring()
    
    def stop_discovery(self):
        """Stop the discovery process"""
        self.is_running = False
        self.logger.info("Discovery process stopped by user")
    
    def _explore_pane(self, pane_name: str):
        """Explore a specific System Settings pane"""
        try:
            # Navigate to the pane
            if not self.navigator.navigate_to_pane(pane_name):
                self.logger.warning(f"Could not navigate to pane: {pane_name}")
                return
            
            # Wait for pane to load
            time.sleep(2)
            
            # Get clickable elements
            elements = self.navigator.get_clickable_elements()
            self.logger.info(f"Found {len(elements)} clickable elements in {pane_name}")
            
            # Interact with each element
            for element in elements:
                if not self.is_running:
                    break
                
                self._interact_with_element(element)
                time.sleep(0.5)  # Small delay between interactions
            
        except Exception as e:
            self.logger.error(f"Error exploring pane {pane_name}: {e}")
    
    def _interact_with_element(self, element: Dict[str, str]):
        """Interact with a UI element and monitor for authorization"""
        element_name = element['name']
        element_path = element['path']
        
        try:
            # Skip if hardware-dependent and not available
            if self.hardware_manager.should_skip_setting(element_path):
                return
            
            self.logger.debug(f"Interacting with element: {element_path}")
            
            # Record timestamp before interaction
            before_timestamp = datetime.now()
            
            # Notify system monitor about potential authorization trigger
            self.system_monitor.simulate_authorization_trigger(element_path)
            
            # Click the element
            if self.navigator.click_element(element_name):
                # Wait briefly for any authorization prompts
                time.sleep(1)
                
                # Check for authorization events after interaction
                new_events = self.system_monitor.get_events_since(before_timestamp)
                
                if new_events:
                    self.logger.info(f"Authorization detected for {element_path}")
                    
                    # Record discovery result
                    result = {
                        'element_path': element_path,
                        'element_name': element_name,
                        'element_type': element.get('type', 'unknown'),
                        'authorization_events': [event.to_dict() for event in new_events],
                        'timestamp': datetime.now().isoformat(),
                        'hardware_profile': self.hardware_manager.get_hardware_profile()
                    }
                    
                    self.discovery_results.append(result)
                
                # Handle any dialog boxes or confirmation prompts
                self._handle_dialogs()
            
        except Exception as e:
            self.logger.error(f"Error interacting with element {element_path}: {e}")
    
    def _handle_dialogs(self):
        """Handle any dialog boxes that appear after clicking elements"""
        try:
            # Check for common dialog types and handle them appropriately
            script = '''
            tell application "System Events"
                if exists window "SecurityAgent" then
                    -- Authorization dialog appeared
                    click button "Cancel" of window "SecurityAgent"
                    delay 0.5
                    return "auth_dialog"
                else if exists alert then
                    -- Generic alert dialog
                    click button "OK" of alert
                    delay 0.5
                    return "alert_dialog"
                else if exists sheet 1 of window 1 of process "System Settings" then
                    -- Settings sheet appeared
                    click button "Cancel" of sheet 1 of window 1 of process "System Settings"
                    delay 0.5
                    return "settings_sheet"
                end if
                return "no_dialog"
            end tell
            '''
            
            result = subprocess.run(['osascript', '-e', script], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                dialog_type = result.stdout.strip()
                if dialog_type != "no_dialog":
                    self.logger.info(f"Handled dialog: {dialog_type}")
            
        except Exception as e:
            self.logger.debug(f"Error handling dialogs: {e}")
    
    def _on_authorization_event(self, event: AuthorizationEvent):
        """Callback for when authorization events are detected"""
        self.logger.info(f"Authorization event detected: {event.right_name}")
    
    def _generate_discovery_report(self):
        """Generate final discovery report"""
        try:
            report = {
                'discovery_session': {
                    'start_time': self.start_time.isoformat() if self.start_time else None,
                    'end_time': datetime.now().isoformat(),
                    'duration_seconds': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
                    'total_authorizations_found': len(self.discovery_results),
                    'hardware_profile': self.hardware_manager.get_hardware_profile(),
                    'unavailable_features': self.hardware_manager.get_unavailable_features()
                },
                'authorization_results': self.discovery_results,
                'system_monitor_stats': self.system_monitor.get_summary_stats(),
                'all_authorization_events': [event.to_dict() for event in self.system_monitor.get_authorization_events()]
            }
            
            # Save report to file
            import json
            report_filename = f"auth_discovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report_path = f"data/{report_filename}"
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Discovery report saved to: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating discovery report: {e}")
    
    def get_progress(self) -> Dict[str, Any]:
        """Get current discovery progress"""
        return {
            'is_running': self.is_running,
            'progress_percent': self.progress,
            'total_items': self.total_items,
            'authorizations_found': len(self.discovery_results),
            'current_path': self.navigator.current_path,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'elapsed_seconds': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        }
    
    def get_results(self) -> List[Dict]:
        """Get current discovery results"""
        return self.discovery_results.copy()
    
    def get_authorization_events(self) -> List[AuthorizationEvent]:
        """Get all authorization events detected"""
        return self.system_monitor.get_authorization_events()
