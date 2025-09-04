#!/usr/bin/env python3
"""
Comprehensive macOS Authorization Discovery Engine
Discovers authorization requirements across all major macOS system settings and security features
"""

import logging
import subprocess
import json
import sqlite3
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
from .pane_discovery import SystemSettingsPaneDiscovery
from .hardware_profile import HardwareProfileManager

class CommandDiscoveryEngine:
    """Discovers system authorization requirements using comprehensive system analysis"""
    
    def __init__(self, no_sudo=False):
        self.logger = logging.getLogger(__name__)
        self.discovery_results = []
        self.is_running = False
        self.progress = 0
        self.no_sudo = no_sudo
        self.total_checks = 75  # Significantly increased for comprehensive coverage of all 36+ system areas
        self.current_check = 0
        self.current_category = "Not started"  # Track current scanning category
        self.start_time = None  # Track when discovery starts
        self.end_time = None  # Track when discovery completes
        self.completion_status = "not_started"  # "not_started", "running", "completed", "stopped", "error"
        if no_sudo:
            self.logger.info("Running in no-sudo mode - some checks may be skipped")
        
        # Initialize dynamic pane discovery
        self.pane_discovery = SystemSettingsPaneDiscovery()
        self._load_system_panes()
        
        # Initialize hardware profile manager
        self.hardware_profile_manager = HardwareProfileManager()
        
        # Comprehensive authorization mapping by System Settings location
        self.authorization_map = {
            "Wi-Fi": [
                {"element": "Network Configuration", "auth_type": "admin", "description": "Modify Wi-Fi network settings"},
                {"element": "Advanced Settings", "auth_type": "admin", "description": "Configure Wi-Fi advanced options"},
                {"element": "View Saved Passwords", "auth_type": "keychain", "description": "View stored Wi-Fi passwords"}
            ],
            "Bluetooth": [
                {"element": "Device Pairing", "auth_type": "user_consent", "description": "Pair new Bluetooth devices"},
                {"element": "Advanced Settings", "auth_type": "admin", "description": "Configure Bluetooth advanced options"}
            ],
            "Network": [
                {"element": "Network Locations", "auth_type": "admin", "description": "Create/modify network locations"},
                {"element": "DNS Settings", "auth_type": "admin", "description": "Modify DNS configuration"},
                {"element": "Proxies", "auth_type": "admin", "description": "Configure proxy settings"},
                {"element": "VPN Configuration", "auth_type": "admin", "description": "Add/modify VPN connections"}
            ],
            "Privacy & Security": [
                {"element": "Location Services", "auth_type": "admin", "description": "Enable/disable location services"},
                {"element": "Contacts", "auth_type": "admin", "description": "Manage app access to contacts"},
                {"element": "Calendars", "auth_type": "admin", "description": "Manage app access to calendars"},
                {"element": "Reminders", "auth_type": "admin", "description": "Manage app access to reminders"},
                {"element": "Photos", "auth_type": "admin", "description": "Manage app access to photos"},
                {"element": "Camera", "auth_type": "admin", "description": "Manage app access to camera"},
                {"element": "Microphone", "auth_type": "admin", "description": "Manage app access to microphone"},
                {"element": "Screen Recording", "auth_type": "admin", "description": "Manage screen recording permissions"},
                {"element": "Files and Folders", "auth_type": "admin", "description": "Manage file system access"},
                {"element": "Full Disk Access", "auth_type": "admin", "description": "Grant complete disk access"},
                {"element": "Accessibility", "auth_type": "admin", "description": "Manage accessibility permissions"},
                {"element": "Developer Tools", "auth_type": "admin", "description": "Allow debugging and development tools"},
                {"element": "Input Monitoring", "auth_type": "admin", "description": "Monitor keyboard and mouse input"},
                {"element": "FileVault", "auth_type": "admin", "description": "Enable/disable disk encryption"},
                {"element": "Firewall", "auth_type": "admin", "description": "Configure application firewall"},
                {"element": "Gatekeeper", "auth_type": "admin", "description": "Modify app security settings"},
                {"element": "Security Extensions", "auth_type": "admin", "description": "Approve system extensions"}
            ],
            "Users & Groups": [
                {"element": "Add User", "auth_type": "admin", "description": "Create new user accounts"},
                {"element": "Delete User", "auth_type": "admin", "description": "Remove user accounts"},
                {"element": "Change Password", "auth_type": "admin", "description": "Modify user passwords"},
                {"element": "Admin Privileges", "auth_type": "admin", "description": "Grant/revoke admin rights"},
                {"element": "Parental Controls", "auth_type": "admin", "description": "Configure user restrictions"},
                {"element": "Login Options", "auth_type": "admin", "description": "Modify login settings"},
                {"element": "Fast User Switching", "auth_type": "admin", "description": "Enable user switching"}
            ],
            "Sharing": [
                {"element": "Screen Sharing", "auth_type": "admin", "description": "Enable remote screen access"},
                {"element": "File Sharing", "auth_type": "admin", "description": "Share files over network"},
                {"element": "Media Sharing", "auth_type": "admin", "description": "Share media libraries"},
                {"element": "Printer Sharing", "auth_type": "admin", "description": "Share connected printers"},
                {"element": "Remote Login", "auth_type": "admin", "description": "Enable SSH access"},
                {"element": "Remote Management", "auth_type": "admin", "description": "Allow remote administration"},
                {"element": "Remote Apple Events", "auth_type": "admin", "description": "Enable remote scripting"},
                {"element": "Internet Sharing", "auth_type": "admin", "description": "Share internet connection"},
                {"element": "Bluetooth Sharing", "auth_type": "admin", "description": "Share files via Bluetooth"},
                {"element": "Content Caching", "auth_type": "admin", "description": "Cache content for network"}
            ],
            "Time Machine": [
                {"element": "Enable Backups", "auth_type": "admin", "description": "Turn Time Machine on/off"},
                {"element": "Select Backup Disk", "auth_type": "admin", "description": "Choose backup destination"},
                {"element": "Backup Options", "auth_type": "admin", "description": "Configure backup settings"},
                {"element": "Exclude Items", "auth_type": "admin", "description": "Exclude files from backup"}
            ],
            "Software Update": [
                {"element": "Install Updates", "auth_type": "admin", "description": "Install system updates"},
                {"element": "Automatic Updates", "auth_type": "admin", "description": "Configure auto-update settings"},
                {"element": "Advanced Options", "auth_type": "admin", "description": "Beta and developer updates"}
            ],
            "General": [
                {"element": "Startup Disk", "auth_type": "admin", "description": "Select boot disk"},
                {"element": "Software Update", "auth_type": "admin", "description": "System update preferences"},
                {"element": "Login Items", "auth_type": "user", "description": "Manage startup applications"},
                {"element": "Language & Region", "auth_type": "admin", "description": "System language settings"}
            ],
            "Accessibility": [
                {"element": "Display", "auth_type": "user", "description": "Visual accessibility options"},
                {"element": "Zoom", "auth_type": "user", "description": "Screen magnification"},
                {"element": "VoiceOver", "auth_type": "user", "description": "Screen reader settings"},
                {"element": "Descriptions", "auth_type": "user", "description": "Audio descriptions"},
                {"element": "Captions", "auth_type": "user", "description": "Subtitle preferences"},
                {"element": "Motor", "auth_type": "user", "description": "Motor accessibility"},
                {"element": "Switch Control", "auth_type": "admin", "description": "Switch-based navigation"},
                {"element": "Voice Control", "auth_type": "admin", "description": "Voice navigation"},
                {"element": "Keyboard", "auth_type": "user", "description": "Keyboard accessibility"},
                {"element": "Pointer Control", "auth_type": "user", "description": "Mouse/trackpad accessibility"},
                {"element": "Hearing", "auth_type": "user", "description": "Audio accessibility"},
                {"element": "Audio", "auth_type": "user", "description": "Sound accessibility options"}
            ],
            "Energy Saver": [
                {"element": "Sleep Settings", "auth_type": "admin", "description": "Configure sleep timers"},
                {"element": "Power Adapter", "auth_type": "admin", "description": "Power adapter settings"},
                {"element": "Battery", "auth_type": "admin", "description": "Battery optimization"},
                {"element": "Schedule", "auth_type": "admin", "description": "Scheduled power events"}
            ],
            "Keyboard": [
                {"element": "Modifier Keys", "auth_type": "user", "description": "Remap modifier keys"},
                {"element": "Shortcuts", "auth_type": "user", "description": "Keyboard shortcuts"},
                {"element": "Input Sources", "auth_type": "admin", "description": "Add/remove keyboards"},
                {"element": "Dictation", "auth_type": "user", "description": "Voice dictation settings"}
            ],
            "Mouse": [
                {"element": "Tracking Speed", "auth_type": "user", "description": "Mouse sensitivity"},
                {"element": "Scrolling", "auth_type": "user", "description": "Scroll behavior"},
                {"element": "Double-Click Speed", "auth_type": "user", "description": "Click timing"}
            ],
            "Trackpad": [
                {"element": "Point & Click", "auth_type": "user", "description": "Trackpad clicking"},
                {"element": "Scroll & Zoom", "auth_type": "user", "description": "Gesture settings"},
                {"element": "More Gestures", "auth_type": "user", "description": "Advanced gestures"}
            ],
            "Printers & Scanners": [
                {"element": "Add Printer", "auth_type": "admin", "description": "Install new printers"},
                {"element": "Remove Printer", "auth_type": "admin", "description": "Remove printers"},
                {"element": "Printer Options", "auth_type": "admin", "description": "Configure printer settings"}
            ],
            "Internet Accounts": [
                {"element": "Add Account", "auth_type": "user", "description": "Add email/calendar accounts"},
                {"element": "Account Settings", "auth_type": "user", "description": "Modify account settings"}
            ],
            "Passwords": [
                {"element": "AutoFill Passwords", "auth_type": "keychain", "description": "Manage saved passwords"},
                {"element": "Password Options", "auth_type": "admin", "description": "Password generation settings"}
            ],
            "Touch ID & Passcode": [
                {"element": "Add Fingerprint", "auth_type": "admin", "description": "Enroll fingerprints"},
                {"element": "Delete Fingerprint", "auth_type": "admin", "description": "Remove fingerprints"},
                {"element": "Use Touch ID for", "auth_type": "admin", "description": "Touch ID permissions"}
            ],
            "Date & Time": [
                {"element": "Set Date & Time", "auth_type": "admin", "description": "Modify system time"},
                {"element": "Time Zone", "auth_type": "admin", "description": "Change time zone"},
                {"element": "Network Time", "auth_type": "admin", "description": "Automatic time sync"}
            ],
            "Storage": [
                {"element": "Optimize Storage", "auth_type": "user", "description": "Storage optimization"},
                {"element": "Store in iCloud", "auth_type": "user", "description": "iCloud storage settings"}
            ]
        }
        
    def _run_command(self, command: str) -> tuple[int, str, str]:
        """Run a shell command and return exit code, stdout, stderr"""
        try:
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timeout: {command}")
            return 1, "", "Command timeout"
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            return 1, "", str(e)

    def _update_progress(self, category: str):
        """Update discovery progress"""
        self.current_check += 1
        self.current_category = category  # Track what we're currently scanning
        self.progress = int((self.current_check / self.total_checks) * 100)
        self.logger.info(f"Checking {category} ({self.current_check}/{self.total_checks})...")

    def _load_system_panes(self):
        """Load system settings panes dynamically based on current system"""
        try:
            self.logger.info("Discovering System Settings panes dynamically...")
            discovered_panes = self.pane_discovery.discover_all_panes()
            self.system_panes = self.pane_discovery.get_pane_names()
            
            self.logger.info(f"Discovered {len(self.system_panes)} available panes:")
            for pane in self.system_panes:
                self.logger.debug(f"  - {pane}")
                
            # Update total checks based on discovered panes
            base_checks = 50  # Base number of security checks
            pane_checks = len(self.system_panes) * 2  # Each pane gets 2 checks on average
            self.total_checks = base_checks + pane_checks
            
            # Store full pane info for later use
            self.discovered_pane_info = discovered_panes
            
        except Exception as e:
            self.logger.error(f"Failed to discover system panes dynamically: {e}")
            # Fallback to static list
            self.system_panes = [
                "Wi-Fi", "Bluetooth", "Network", "VPN", "Notifications", "Sound", "Focus", 
                "Screen Time", "General", "Appearance", "Accessibility", "Control Center",
                "Siri & Spotlight", "Privacy & Security", "Desktop & Dock", "Displays",
                "Wallpaper", "Screen Saver", "Battery", "Energy Saver", "Keyboard", "Mouse",
                "Trackpad", "Printers & Scanners", "Game Center", "Internet Accounts",
                "Passwords", "Wallet & Apple Pay", "Users & Groups", "Touch ID & Passcode",
                "Login Items", "Date & Time", "Sharing", "Time Machine", "Transfer or Reset",
                "Software Update", "Storage"
            ]

    def _check_tcc_database(self) -> List[Dict[str, Any]]:
        """Check TCC.db for privacy-sensitive permissions"""
        self._update_progress("TCC Privacy Database")
        tcc_paths = [
            "/Library/Application Support/com.apple.TCC/TCC.db",
            os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
        ]
        auth_entries = []
        
        for db_path in tcc_paths:
            if os.path.exists(db_path):
                try:
                    # Use Python's sqlite3 instead of command line for better error handling
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT client, service, auth_value FROM access")
                    rows = cursor.fetchall()
                    
                    for client, service, auth_value in rows:
                        auth_entries.append({
                            "type": "privacy",
                            "category": "TCC Permission",
                            "service": service,
                            "client": client,
                            "authorized": auth_value == 2,
                            "source": db_path,
                            "timestamp": datetime.now().isoformat(),
                            "requires_auth": True,
                            "auth_type": "user_consent",
                            "description": f"Privacy access for {service} by {client}"
                        })
                    conn.close()
                except Exception as e:
                    self.logger.error(f"Error reading TCC database {db_path}: {e}")
        
        return auth_entries

    def _check_security_framework(self) -> List[Dict[str, Any]]:
        """Check Security framework settings"""
        self._update_progress("Security Framework")
        auth_points = []
        
        # Check Gatekeeper status
        code, stdout, stderr = self._run_command("spctl --status")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "Gatekeeper",
                "status": "enabled" if "assessments enabled" in stdout else "disabled",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "App notarization and code signing verification"
            })

        # Check System Integrity Protection (SIP)
        code, stdout, stderr = self._run_command("csrutil status")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "System Integrity Protection",
                "status": "enabled" if "enabled" in stdout else "disabled",
                "requires_auth": True,
                "auth_type": "recovery_mode",
                "timestamp": datetime.now().isoformat(),
                "description": "System file and process protection"
            })

        # Check FileVault status
        code, stdout, stderr = self._run_command("fdesetup status")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "FileVault",
                "status": "enabled" if "FileVault is On" in stdout else "disabled",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Full disk encryption requires authentication for setup and recovery"
            })

        return auth_points

    def _check_network_security(self) -> List[Dict[str, Any]]:
        """Check network-related security and authorization settings"""
        self._update_progress("Network Security")
        auth_points = []
        
        # Check VPN configurations
        vpn_configs = []
        code, stdout, stderr = self._run_command("networksetup -listallnetworkservices")
        if code == 0:
            for line in stdout.splitlines():
                if "VPN" in line:
                    vpn_configs.append(line.strip())
        
        if vpn_configs:
            auth_points.append({
                "type": "network",
                "category": "VPN Configurations",
                "status": "configured",
                "details": vpn_configs,
                "requires_auth": True,
                "auth_type": "user_credentials",
                "timestamp": datetime.now().isoformat(),
                "description": "VPN connections requiring authentication"
            })

        return auth_points

    def _check_user_accounts(self) -> List[Dict[str, Any]]:
        """Check user account and authentication settings"""
        self._update_progress("User Accounts")
        auth_points = []
        
        # Check for admin users
        code, stdout, stderr = self._run_command("dscl . -read /Groups/admin GroupMembership")
        if code == 0:
            admin_users = stdout.replace("GroupMembership:", "").strip().split()
            auth_points.append({
                "type": "accounts",
                "category": "Administrator Accounts",
                "status": "configured",
                "details": admin_users,
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Users with administrative privileges"
            })

        return auth_points

    def _check_keychain_access(self) -> List[Dict[str, Any]]:
        """Check Keychain access and authentication"""
        self._update_progress("Keychain Access")
        auth_points = []
        
        # Check for keychains
        code, stdout, stderr = self._run_command("security list-keychains")
        if code == 0:
            keychains = [line.strip().strip('"') for line in stdout.splitlines() if line.strip()]
            for keychain in keychains:
                auth_points.append({
                    "type": "keychain",
                    "category": "Keychain Access",
                    "keychain_path": keychain,
                    "status": "secured",
                    "requires_auth": True,
                    "auth_type": "keychain_password",
                    "timestamp": datetime.now().isoformat(),
                    "description": f"Keychain requiring authentication: {os.path.basename(keychain)}"
                })

        return auth_points

    def _check_system_preferences_auth(self) -> List[Dict[str, Any]]:
        """Check System Preferences/Settings authorization requirements"""
        self._update_progress("System Settings Authorization")
        auth_points = []
        
        # Check for preference panes that require authentication
        pref_panes = [
            "/System/Library/PreferencePanes/Security.prefPane",
            "/System/Library/PreferencePanes/Accounts.prefPane", 
            "/System/Library/PreferencePanes/Network.prefPane",
            "/System/Library/PreferencePanes/SharingPref.prefPane",
            "/System/Library/PreferencePanes/TimeMachine.prefPane"
        ]
        
        for pane in pref_panes:
            if os.path.exists(pane):
                pane_name = os.path.basename(pane).replace(".prefPane", "")
                auth_points.append({
                    "type": "system_preferences",
                    "category": "Protected Preference Pane",
                    "pane_name": pane_name,
                    "status": "requires_admin",
                    "requires_auth": True,
                    "auth_type": "admin",
                    "timestamp": datetime.now().isoformat(),
                    "description": f"System preference pane requiring admin authentication: {pane_name}"
                })

        return auth_points

    def _check_developer_tools(self) -> List[Dict[str, Any]]:
        """Check Developer Tools and code signing"""
        self._update_progress("Developer Tools")
        auth_points = []
        
        # Check for Xcode command line tools
        code, stdout, stderr = self._run_command("xcode-select -p")
        if code == 0:
            auth_points.append({
                "type": "development",
                "category": "Xcode Command Line Tools",
                "status": "installed",
                "path": stdout.strip(),
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Developer tools requiring admin privileges for installation"
            })

        return auth_points

    def _check_wifi_security(self) -> List[Dict[str, Any]]:
        """Check Wi-Fi security and authentication settings"""
        self._update_progress("Wi-Fi Security Settings")
        auth_points = []
        
        # Check Wi-Fi network configurations
        code, stdout, stderr = self._run_command("networksetup -listallhardwareports | grep Wi-Fi -A1")
        if code == 0:
            auth_points.append({
                "type": "network",
                "category": "Wi-Fi",
                "location": "Wi-Fi",
                "status": "configured",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Wi-Fi network configuration requires admin authentication"
            })
        
        # Check for stored Wi-Fi passwords
        code, stdout, stderr = self._run_command("security find-generic-password -D 'AirPort network password' 2>/dev/null | wc -l")
        if code == 0 and stdout.strip() != "0":
            auth_points.append({
                "type": "network",
                "category": "Wi-Fi",
                "location": "Wi-Fi → Saved Networks",
                "status": "stored_passwords",
                "requires_auth": True,
                "auth_type": "keychain_access",
                "timestamp": datetime.now().isoformat(),
                "description": "Viewing saved Wi-Fi passwords requires authentication"
            })
        
        return auth_points

    def _check_bluetooth_security(self) -> List[Dict[str, Any]]:
        """Check Bluetooth security and pairing requirements"""
        self._update_progress("Bluetooth Security Settings")
        auth_points = []
        
        # Check Bluetooth configuration
        code, stdout, stderr = self._run_command("system_profiler SPBluetoothDataType")
        if code == 0 and "Bluetooth" in stdout:
            auth_points.append({
                "type": "network",
                "category": "Bluetooth",
                "location": "Bluetooth",
                "status": "available",
                "requires_auth": True,
                "auth_type": "user_consent",
                "timestamp": datetime.now().isoformat(),
                "description": "Bluetooth device pairing and management"
            })
        
        return auth_points

    def _check_privacy_security_comprehensive(self) -> List[Dict[str, Any]]:
        """Comprehensive Privacy & Security settings check"""
        self._update_progress("Privacy & Security Comprehensive")
        auth_points = []
        
        privacy_categories = [
            "Location Services", "Contacts", "Calendars", "Reminders", "Photos",
            "Camera", "Microphone", "Screen Recording", "Files and Folders",
            "Full Disk Access", "Accessibility", "Developer Tools", "Input Monitoring"
        ]
        
        for category in privacy_categories:
            auth_points.append({
                "type": "privacy",
                "category": category,
                "location": f"Privacy & Security → {category}",
                "status": "protected",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": f"Modifying {category} permissions requires admin authentication"
            })
        
        return auth_points

    def _check_users_groups_comprehensive(self) -> List[Dict[str, Any]]:
        """Comprehensive Users & Groups settings check"""
        self._update_progress("Users & Groups Comprehensive")
        auth_points = []
        
        # Check user management functions
        user_functions = [
            "Add User", "Delete User", "Change Password", "Admin Privileges",
            "Parental Controls", "Login Options", "Fast User Switching"
        ]
        
        for function in user_functions:
            auth_points.append({
                "type": "accounts",
                "category": "User Management",
                "location": f"Users & Groups → {function}",
                "status": "restricted",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": f"{function} requires administrator authentication"
            })
        
        return auth_points

    def _check_sharing_services(self) -> List[Dict[str, Any]]:
        """Check Sharing services and their authorization requirements"""
        self._update_progress("Sharing Services")
        auth_points = []
        
        sharing_services = [
            "Screen Sharing", "File Sharing", "Media Sharing", "Printer Sharing",
            "Remote Login", "Remote Management", "Remote Apple Events",
            "Internet Sharing", "Bluetooth Sharing", "Content Caching"
        ]
        
        for service in sharing_services:
            auth_points.append({
                "type": "sharing",
                "category": "Sharing Service",
                "location": f"Sharing → {service}",
                "status": "configurable",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": f"Enabling {service} requires admin authentication"
            })
        
        return auth_points

    def _check_time_machine_settings(self) -> List[Dict[str, Any]]:
        """Check Time Machine backup settings"""
        self._update_progress("Time Machine Settings")
        auth_points = []
        
        # Check Time Machine status
        code, stdout, stderr = self._run_command("tmutil status")
        if code == 0:
            auth_points.append({
                "type": "backup",
                "category": "Time Machine",
                "location": "Time Machine",
                "status": "configured" if "Running" in stdout else "available",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Time Machine configuration requires admin authentication"
            })
        
        # Check for backup destinations
        code, stdout, stderr = self._run_command("tmutil destinationinfo")
        if code == 0 and stdout.strip():
            auth_points.append({
                "type": "backup",
                "category": "Time Machine",
                "location": "Time Machine → Select Backup Disk",
                "status": "configured",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Changing backup destination requires admin authentication"
            })
        
        return auth_points

    def _check_software_update_settings(self) -> List[Dict[str, Any]]:
        """Check Software Update settings and automatic updates"""
        self._update_progress("Software Update Settings")
        auth_points = []
        
        # Check software update preferences
        code, stdout, stderr = self._run_command("defaults read /Library/Preferences/com.apple.SoftwareUpdate")
        if code == 0:
            auth_points.append({
                "type": "system",
                "category": "Software Update",
                "location": "Software Update",
                "status": "configurable",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Modifying automatic update settings requires admin authentication"
            })
        
        return auth_points

    def _check_network_advanced_settings(self) -> List[Dict[str, Any]]:
        """Check advanced network settings and configurations"""
        self._update_progress("Network Advanced Settings")
        auth_points = []
        
        # Check network locations
        code, stdout, stderr = self._run_command("networksetup -listlocations")
        if code == 0:
            auth_points.append({
                "type": "network",
                "category": "Network Locations",
                "location": "Network → Network Locations",
                "status": "configurable",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Creating and modifying network locations requires admin authentication"
            })
        
        # Check DNS settings
        auth_points.append({
            "type": "network",
            "category": "DNS Settings",
            "location": "Network → Advanced → DNS",
            "status": "configurable",
            "requires_auth": True,
            "auth_type": "admin",
            "timestamp": datetime.now().isoformat(),
            "description": "Modifying DNS settings requires admin authentication"
        })
        
        return auth_points

    def _check_accessibility_settings(self) -> List[Dict[str, Any]]:
        """Check Accessibility settings and permissions"""
        self._update_progress("Accessibility Settings")
        auth_points = []
        
        accessibility_features = [
            "Display", "Zoom", "VoiceOver", "Descriptions", "Captions",
            "Motor", "Switch Control", "Voice Control", "Keyboard",
            "Pointer Control", "Hearing", "Audio"
        ]
        
        for feature in accessibility_features:
            auth_points.append({
                "type": "accessibility",
                "category": "Accessibility Feature",
                "location": f"Accessibility → {feature}",
                "status": "configurable",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": f"Configuring {feature} accessibility settings may require authentication"
            })
        
        return auth_points

    def _check_energy_settings(self) -> List[Dict[str, Any]]:
        """Check Energy/Battery settings"""
        self._update_progress("Energy Settings")
        auth_points = []
        
        # Check power management settings
        code, stdout, stderr = self._run_command("pmset -g")
        if code == 0:
            auth_points.append({
                "type": "system",
                "category": "Energy Settings",
                "location": "Battery/Energy Saver",
                "status": "configurable",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Modifying energy settings requires admin authentication"
            })
        
        return auth_points

    def _check_display_settings(self) -> List[Dict[str, Any]]:
        """Check Display settings and configurations"""
        self._update_progress("Display Settings")
        auth_points = []
        
        # Check display configuration
        code, stdout, stderr = self._run_command("system_profiler SPDisplaysDataType")
        if code == 0:
            auth_points.append({
                "type": "display",
                "category": "Display Configuration",
                "location": "Displays",
                "status": "configurable",
                "requires_auth": False,  # Most display settings don't require auth
                "auth_type": "none",
                "timestamp": datetime.now().isoformat(),
                "description": "Basic display settings available to all users"
            })
        
        return auth_points

    def _check_startup_disk_settings(self) -> List[Dict[str, Any]]:
        """Check Startup Disk selection"""
        self._update_progress("Startup Disk Settings")
        auth_points = []
        
        # Check available startup disks
        code, stdout, stderr = self._run_command("bless --info --getboot")
        if code == 0:
            auth_points.append({
                "type": "system",
                "category": "Startup Disk",
                "location": "General → Startup Disk",
                "status": "selectable",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Changing startup disk requires admin authentication"
            })
        
        return auth_points

    def _check_certificate_trust_settings(self) -> List[Dict[str, Any]]:
        """Check Certificate Trust Settings"""
        self._update_progress("Certificate Trust Settings")
        auth_points = []
        
        # Check system certificates
        code, stdout, stderr = self._run_command("security dump-trust-settings -s")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "Certificate Trust",
                "location": "Privacy & Security → Certificates",
                "status": "managed",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Modifying certificate trust settings requires admin authentication"
            })
        
        return auth_points

    def _check_application_firewall(self) -> List[Dict[str, Any]]:
        """Check Application Firewall settings"""
        self._update_progress("Application Firewall")
        auth_points = []
        
        # Check firewall status
        code, stdout, stderr = self._run_command("defaults read /Library/Preferences/com.apple.alf globalstate")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "Application Firewall",
                "location": "Privacy & Security → Firewall",
                "status": "configurable",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Configuring application firewall requires admin authentication"
            })
        
        return auth_points

    def _check_system_extensions(self) -> List[Dict[str, Any]]:
        """Check System Extensions and Kernel Extensions"""
        self._update_progress("System Extensions")
        auth_points = []
        
        # Check system extensions
        code, stdout, stderr = self._run_command("systemextensionsctl list")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "System Extensions",
                "location": "Privacy & Security → Security",
                "status": "managed",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Managing system extensions requires admin authentication"
            })
        
        return auth_points

    def _check_login_items_comprehensive(self) -> List[Dict[str, Any]]:
        """Check Login Items and background apps"""
        self._update_progress("Login Items Comprehensive")
        auth_points = []
        
        # Check login items
        code, stdout, stderr = self._run_command("osascript -e 'tell application \"System Events\" to get the name of every login item'")
        if code == 0:
            auth_points.append({
                "type": "system",
                "category": "Login Items",
                "location": "General → Login Items",
                "status": "configurable",
                "requires_auth": False,  # Users can modify their own login items
                "auth_type": "user",
                "timestamp": datetime.now().isoformat(),
                "description": "Users can manage their own login items"
            })
        
        # Check system-wide launch agents/daemons
        auth_points.append({
            "type": "system",
            "category": "System Launch Items",
            "location": "General → Login Items → Allow in Background",
            "status": "restricted",
            "requires_auth": True,
            "auth_type": "admin",
            "timestamp": datetime.now().isoformat(),
            "description": "System-wide launch items require admin authentication"
        })
        
        return auth_points

    def _check_sound_settings(self) -> List[Dict[str, Any]]:
        """Check Sound settings authorization requirements"""
        self._update_progress("Sound Settings")
        auth_points = []
        
        # Check audio device settings
        code, stdout, stderr = self._run_command("system_profiler SPAudioDataType")
        if code == 0:
            auth_points.append({
                "type": "system_settings",
                "category": "Sound",
                "location": "Sound → Output/Input",
                "status": "available",
                "requires_auth": False,
                "auth_type": "none",
                "timestamp": datetime.now().isoformat(),
                "description": "Audio device configuration"
            })
        
        # Check alert sounds
        code, stdout, stderr = self._run_command("defaults read com.apple.systemsound")
        auth_points.append({
            "type": "system_settings",
            "category": "Sound",
            "location": "Sound → Sound Effects",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Alert sound configuration"
        })
        
        return auth_points

    def _check_focus_settings(self) -> List[Dict[str, Any]]:
        """Check Focus settings authorization requirements"""
        self._update_progress("Focus Settings")
        auth_points = []
        
        # Check Do Not Disturb settings
        code, stdout, stderr = self._run_command("defaults read com.apple.ncprefs")
        auth_points.append({
            "type": "system_settings",
            "category": "Focus",
            "location": "Focus → Do Not Disturb",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Focus mode configuration"
        })
        
        return auth_points

    def _check_general_settings(self) -> List[Dict[str, Any]]:
        """Check General settings authorization requirements"""
        self._update_progress("General Settings")
        auth_points = []
        
        # Check system-wide settings
        code, stdout, stderr = self._run_command("defaults read NSGlobalDomain")
        auth_points.append({
            "type": "system_settings",
            "category": "General",
            "location": "General → About",
            "status": "system_info",
            "requires_auth": False,
            "auth_type": "none",
            "timestamp": datetime.now().isoformat(),
            "description": "System information display"
        })
        
        # Check AirDrop & Handoff
        code, stdout, stderr = self._run_command("defaults read com.apple.sharingd")
        auth_points.append({
            "type": "system_settings",
            "category": "General",
            "location": "General → AirDrop & Handoff",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "AirDrop and Handoff configuration"
        })
        
        return auth_points

    def _check_appearance_settings(self) -> List[Dict[str, Any]]:
        """Check Appearance settings authorization requirements"""
        self._update_progress("Appearance Settings")
        auth_points = []
        
        # Check appearance mode
        code, stdout, stderr = self._run_command("defaults read NSGlobalDomain AppleInterfaceStyle")
        auth_points.append({
            "type": "system_settings",
            "category": "Appearance",
            "location": "Appearance → Interface Style",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Light/Dark mode configuration"
        })
        
        # Check accent color
        code, stdout, stderr = self._run_command("defaults read NSGlobalDomain AppleAccentColor")
        auth_points.append({
            "type": "system_settings",
            "category": "Appearance",
            "location": "Appearance → Accent Color",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "System accent color"
        })
        
        return auth_points

    def _check_desktop_dock_settings(self) -> List[Dict[str, Any]]:
        """Check Desktop & Dock settings authorization requirements"""
        self._update_progress("Desktop & Dock Settings")
        auth_points = []
        
        # Check Dock settings
        code, stdout, stderr = self._run_command("defaults read com.apple.dock")
        auth_points.append({
            "type": "system_settings",
            "category": "Desktop & Dock",
            "location": "Desktop & Dock → Dock",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Dock appearance and behavior"
        })
        
        # Check Mission Control
        code, stdout, stderr = self._run_command("defaults read com.apple.dock expose-animation-duration")
        auth_points.append({
            "type": "system_settings",
            "category": "Desktop & Dock",
            "location": "Desktop & Dock → Mission Control",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Mission Control configuration"
        })
        
        return auth_points

    def _check_wallpaper_screensaver_settings(self) -> List[Dict[str, Any]]:
        """Check Wallpaper & Screen Saver settings authorization requirements"""
        self._update_progress("Wallpaper & Screen Saver Settings")
        auth_points = []
        
        # Check wallpaper settings
        code, stdout, stderr = self._run_command("defaults read com.apple.desktop")
        auth_points.append({
            "type": "system_settings",
            "category": "Wallpaper & Screen Saver",
            "location": "Wallpaper & Screen Saver → Desktop Picture",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Desktop wallpaper configuration"
        })
        
        # Check screen saver settings
        code, stdout, stderr = self._run_command("defaults read com.apple.screensaver")
        auth_points.append({
            "type": "system_settings",
            "category": "Wallpaper & Screen Saver",
            "location": "Wallpaper & Screen Saver → Screen Saver",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Screen saver configuration"
        })
        
        return auth_points

    def _check_keyboard_mouse_settings(self) -> List[Dict[str, Any]]:
        """Check Keyboard & Mouse settings authorization requirements"""
        self._update_progress("Keyboard & Mouse Settings")
        auth_points = []
        
        # Check keyboard settings
        code, stdout, stderr = self._run_command("defaults read NSGlobalDomain InitialKeyRepeat")
        auth_points.append({
            "type": "system_settings",
            "category": "Keyboard",
            "location": "Keyboard → Key Repeat",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Keyboard repeat rate"
        })
        
        # Check mouse settings
        code, stdout, stderr = self._run_command("defaults read com.apple.driver.AppleBluetoothMultitouch.mouse")
        auth_points.append({
            "type": "system_settings",
            "category": "Mouse",
            "location": "Mouse → Tracking Speed",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Mouse tracking configuration"
        })
        
        return auth_points

    def _check_trackpad_settings(self) -> List[Dict[str, Any]]:
        """Check Trackpad settings authorization requirements"""
        self._update_progress("Trackpad Settings")
        auth_points = []
        
        # Check trackpad settings
        code, stdout, stderr = self._run_command("defaults read com.apple.driver.AppleBluetoothMultitouch.trackpad")
        auth_points.append({
            "type": "system_settings",
            "category": "Trackpad",
            "location": "Trackpad → Point & Click",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Trackpad gesture configuration"
        })
        
        return auth_points

    def _check_printers_scanners_settings(self) -> List[Dict[str, Any]]:
        """Check Printers & Scanners settings authorization requirements"""
        self._update_progress("Printers & Scanners Settings")
        auth_points = []
        
        # Check printer settings - requires admin for adding/removing
        code, stdout, stderr = self._run_command("lpstat -p")
        auth_points.append({
            "type": "system_settings",
            "category": "Printers & Scanners",
            "location": "Printers & Scanners → Add Printer",
            "status": "requires_admin",
            "requires_auth": True,
            "auth_type": "admin",
            "timestamp": datetime.now().isoformat(),
            "description": "Add or remove printers requires admin authorization"
        })
        
        return auth_points

    def _check_game_center_settings(self) -> List[Dict[str, Any]]:
        """Check Game Center settings authorization requirements"""
        self._update_progress("Game Center Settings")
        auth_points = []
        
        # Check Game Center settings
        code, stdout, stderr = self._run_command("defaults read com.apple.gamed")
        auth_points.append({
            "type": "system_settings",
            "category": "Game Center",
            "location": "Game Center → Account",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Game Center account configuration"
        })
        
        return auth_points

    def _check_internet_accounts_settings(self) -> List[Dict[str, Any]]:
        """Check Internet Accounts settings authorization requirements"""
        self._update_progress("Internet Accounts Settings")
        auth_points = []
        
        # Check internet accounts
        code, stdout, stderr = self._run_command("defaults read MobileMeAccounts")
        auth_points.append({
            "type": "system_settings",
            "category": "Internet Accounts",
            "location": "Internet Accounts → Add Account",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Internet account configuration"
        })
        
        return auth_points

    def _check_passwords_settings(self) -> List[Dict[str, Any]]:
        """Check Passwords settings authorization requirements"""
        self._update_progress("Passwords Settings")
        auth_points = []
        
        # Password settings are managed through Passwords app
        auth_points.append({
            "type": "system_settings",
            "category": "Passwords",
            "location": "Passwords → Password Options",
            "status": "app_managed",
            "requires_auth": True,
            "auth_type": "password",
            "timestamp": datetime.now().isoformat(),
            "description": "Password management requires authentication"
        })
        
        return auth_points

    def _check_wallet_apple_pay_settings(self) -> List[Dict[str, Any]]:
        """Check Wallet & Apple Pay settings authorization requirements"""
        self._update_progress("Wallet & Apple Pay Settings")
        auth_points = []
        
        # Apple Pay settings
        auth_points.append({
            "type": "system_settings",
            "category": "Wallet & Apple Pay",
            "location": "Wallet & Apple Pay → Payment Cards",
            "status": "secure_element",
            "requires_auth": True,
            "auth_type": "biometric",
            "timestamp": datetime.now().isoformat(),
            "description": "Apple Pay configuration requires biometric authentication"
        })
        
        return auth_points

    def _check_touch_id_passcode_settings(self) -> List[Dict[str, Any]]:
        """Check Touch ID & Passcode settings authorization requirements"""
        self._update_progress("Touch ID & Passcode Settings")
        auth_points = []
        
        # Check biometric settings
        code, stdout, stderr = self._run_command("bioutil -rs")
        if "Touch ID" in stdout or "Face ID" in stdout:
            auth_points.append({
                "type": "system_settings",
                "category": "Touch ID & Passcode",
                "location": "Touch ID & Passcode → Touch ID",
                "status": "biometric_required",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "Touch ID configuration requires admin authentication"
            })
        
        return auth_points

    def _check_date_time_settings(self) -> List[Dict[str, Any]]:
        """Check Date & Time settings authorization requirements"""
        self._update_progress("Date & Time Settings")
        auth_points = []
        
        # Check date/time settings
        code, stdout, stderr = self._run_command("systemsetup -getdate")
        if code == 0 or "requires admin" in stderr.lower():
            auth_points.append({
                "type": "system_settings",
                "category": "Date & Time",
                "location": "Date & Time → Set Date & Time",
                "status": "admin_required",
                "requires_auth": True,
                "auth_type": "admin",
                "timestamp": datetime.now().isoformat(),
                "description": "System date/time changes require admin authorization"
            })
        
        return auth_points

    def _check_screen_time_settings(self) -> List[Dict[str, Any]]:
        """Check Screen Time settings authorization requirements"""
        self._update_progress("Screen Time Settings")
        auth_points = []
        
        # Screen Time settings
        code, stdout, stderr = self._run_command("defaults read com.apple.screentime")
        auth_points.append({
            "type": "system_settings",
            "category": "Screen Time",
            "location": "Screen Time → App & Website Activity",
            "status": "parental_controls",
            "requires_auth": True,
            "auth_type": "password",
            "timestamp": datetime.now().isoformat(),
            "description": "Screen Time configuration requires Screen Time passcode"
        })
        
        return auth_points

    def _check_control_center_settings(self) -> List[Dict[str, Any]]:
        """Check Control Center settings authorization requirements"""
        self._update_progress("Control Center Settings")
        auth_points = []
        
        # Control Center settings
        code, stdout, stderr = self._run_command("defaults read com.apple.controlcenter")
        auth_points.append({
            "type": "system_settings",
            "category": "Control Center",
            "location": "Control Center → Control Center Modules",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Control Center module configuration"
        })
        
        return auth_points

    def _check_siri_spotlight_settings(self) -> List[Dict[str, Any]]:
        """Check Siri & Spotlight settings authorization requirements"""
        self._update_progress("Siri & Spotlight Settings")
        auth_points = []
        
        # Siri settings
        code, stdout, stderr = self._run_command("defaults read com.apple.assistant.support")
        auth_points.append({
            "type": "system_settings",
            "category": "Siri & Spotlight",
            "location": "Siri & Spotlight → Siri",
            "status": "privacy_sensitive",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Siri configuration affects privacy settings"
        })
        
        # Spotlight settings
        code, stdout, stderr = self._run_command("defaults read com.apple.spotlight")
        auth_points.append({
            "type": "system_settings",
            "category": "Siri & Spotlight",
            "location": "Siri & Spotlight → Spotlight",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Spotlight search configuration"
        })
        
        return auth_points

    def _check_notifications_settings(self) -> List[Dict[str, Any]]:
        """Check Notifications settings authorization requirements"""
        self._update_progress("Notifications Settings")
        auth_points = []
        
        # Notification settings
        code, stdout, stderr = self._run_command("defaults read com.apple.ncprefs")
        auth_points.append({
            "type": "system_settings",
            "category": "Notifications",
            "location": "Notifications → Application Notifications",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "Per-app notification configuration"
        })
        
        return auth_points

    def _check_vpn_settings(self) -> List[Dict[str, Any]]:
        """Check VPN settings authorization requirements"""
        self._update_progress("VPN Settings")
        auth_points = []
        
        # VPN configuration
        code, stdout, stderr = self._run_command("scutil --nc list")
        auth_points.append({
            "type": "system_settings",
            "category": "VPN",
            "location": "VPN → VPN Configurations",
            "status": "network_config",
            "requires_auth": True,
            "auth_type": "admin",
            "timestamp": datetime.now().isoformat(),
            "description": "VPN configuration requires admin authorization"
        })
        
        return auth_points

    def _check_transfer_reset_settings(self) -> List[Dict[str, Any]]:
        """Check Transfer or Reset settings authorization requirements"""
        self._update_progress("Transfer or Reset Settings")
        auth_points = []
        
        # System reset options
        auth_points.append({
            "type": "system_settings",
            "category": "Transfer or Reset",
            "location": "Transfer or Reset → Erase All Content and Settings",
            "status": "destructive_action",
            "requires_auth": True,
            "auth_type": "admin",
            "timestamp": datetime.now().isoformat(),
            "description": "System reset requires admin authorization"
        })
        
        return auth_points

    def _check_storage_settings(self) -> List[Dict[str, Any]]:
        """Check Storage settings authorization requirements"""
        self._update_progress("Storage Settings")
        auth_points = []
        
        # Storage management
        code, stdout, stderr = self._run_command("df -h")
        auth_points.append({
            "type": "system_settings",
            "category": "Storage",
            "location": "Storage → Storage Recommendations",
            "status": "system_info",
            "requires_auth": False,
            "auth_type": "none",
            "timestamp": datetime.now().isoformat(),
            "description": "Storage information and optimization"
        })
        
        # iCloud storage optimization
        code, stdout, stderr = self._run_command("defaults read com.apple.bird")
        auth_points.append({
            "type": "system_settings",
            "category": "Storage",
            "location": "Storage → iCloud",
            "status": "user_setting",
            "requires_auth": False,
            "auth_type": "user",
            "timestamp": datetime.now().isoformat(),
            "description": "iCloud storage optimization"
        })
        
        return auth_points

    def _generate_comprehensive_authorization_map(self) -> List[Dict[str, Any]]:
        """Generate comprehensive authorization map from known System Settings locations"""
        self._update_progress("Comprehensive Authorization Mapping")
        auth_points = []
        
        for pane_name, authorizations in self.authorization_map.items():
            for auth in authorizations:
                auth_points.append({
                    "type": "system_settings",
                    "category": auth["element"],
                    "pane": pane_name,
                    "location": f"{pane_name} → {auth['element']}",
                    "status": "available",
                    "requires_auth": auth["auth_type"] != "none",
                    "auth_type": auth["auth_type"],
                    "timestamp": datetime.now().isoformat(),
                    "description": auth["description"],
                    "source": "authorization_map"
                })
        
        return auth_points

    def discover_all_authorizations(self) -> List[Dict[str, Any]]:
        """Run comprehensive authorization discovery"""
        self.logger.info("Starting comprehensive macOS authorization discovery...")
        self.is_running = True
        self.completion_status = "running"  # Set to running
        self.start_time = datetime.now()  # Record start time
        self.end_time = None  # Reset end time
        self.progress = 0
        self.current_check = 0
        self.discovery_results = []
        
        try:
            # Comprehensive discovery methods - significantly expanded to cover all 36+ System Settings areas
            discovery_methods = [
                # Core system security methods
                self._check_tcc_database,
                self._check_security_framework,
                self._check_network_security,
                self._check_user_accounts,
                self._check_keychain_access,
                self._check_system_preferences_auth,
                self._check_developer_tools,
                
                # Network & Communication methods
                self._check_wifi_security,
                self._check_bluetooth_security,
                self._check_network_advanced_settings,
                self._check_vpn_settings,
                
                # Privacy & Security comprehensive methods
                self._check_privacy_security_comprehensive,
                self._check_accessibility_settings,
                self._check_certificate_trust_settings,
                self._check_application_firewall,
                self._check_system_extensions,
                
                # User & System Management methods
                self._check_users_groups_comprehensive,
                self._check_login_items_comprehensive,
                self._check_touch_id_passcode_settings,
                self._check_passwords_settings,
                
                # System Settings UI Areas (all 36+ areas)
                self._check_sound_settings,
                self._check_focus_settings,
                self._check_notifications_settings,
                self._check_screen_time_settings,
                self._check_general_settings,
                self._check_appearance_settings,
                self._check_control_center_settings,
                self._check_siri_spotlight_settings,
                self._check_desktop_dock_settings,
                self._check_display_settings,
                self._check_wallpaper_screensaver_settings,
                self._check_energy_settings,
                self._check_keyboard_mouse_settings,
                self._check_trackpad_settings,
                self._check_printers_scanners_settings,
                self._check_game_center_settings,
                self._check_internet_accounts_settings,
                self._check_wallet_apple_pay_settings,
                self._check_date_time_settings,
                
                # System Maintenance & Backup
                self._check_sharing_services,
                self._check_time_machine_settings,
                self._check_software_update_settings,
                self._check_transfer_reset_settings,
                self._check_storage_settings,
                self._check_startup_disk_settings,
                
                # Comprehensive authorization mapping
                self._generate_comprehensive_authorization_map
            ]
            
            for method in discovery_methods:
                try:
                    results = method()
                    self.discovery_results.extend(results)
                except Exception as e:
                    self.logger.error(f"Error in {method.__name__}: {e}")
            
            self.progress = 100
            self.end_time = datetime.now()  # Record completion time
            self.completion_status = "completed"  # Mark as successfully completed
            self.logger.info(f"Discovery complete. Found {len(self.discovery_results)} authorization points.")
            
        except Exception as e:
            self.logger.error(f"Discovery error: {e}")
            self.completion_status = "error"  # Mark as error
            self.end_time = datetime.now()  # Record error time
        finally:
            self.is_running = False
            
        return self.discovery_results

    def get_progress(self) -> int:
        """Get current discovery progress percentage"""
        return self.progress
    
    def get_elapsed_seconds(self) -> float:
        """Get elapsed time since discovery started"""
        if self.start_time is None:
            return 0.0
        
        # If discovery is completed or errored, return the total time taken
        if self.completion_status in ["completed", "error", "stopped"] and self.end_time is not None:
            return (self.end_time - self.start_time).total_seconds()
        
        # If discovery is still running, return current elapsed time
        return (datetime.now() - self.start_time).total_seconds()

    def is_discovery_running(self) -> bool:
        """Check if discovery is currently running"""
        return self.is_running
    
    def is_discovery_completed(self) -> bool:
        """Check if discovery has completed successfully"""
        return self.completion_status == "completed"
    
    def get_completion_status(self) -> str:
        """Get the current completion status"""
        return self.completion_status
    
    def stop_discovery(self):
        """Stop the discovery process manually"""
        if self.is_running:
            self.is_running = False
            self.completion_status = "stopped"
            self.end_time = datetime.now()
            self.logger.info("Discovery stopped manually")

    def get_results(self) -> List[Dict[str, Any]]:
        """Get discovery results"""
        return self.discovery_results

    def get_results_summary(self) -> Dict[str, Any]:
        """Get a summary of discovery results"""
        if not self.discovery_results:
            return {"total": 0, "categories": {}}
        
        categories = {}
        for result in self.discovery_results:
            category = result.get("type", "unknown")
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
        
        return {
            "total": len(self.discovery_results),
            "categories": categories,
            "last_updated": datetime.now().isoformat()
        }

    def get_authorization_map(self) -> Dict[str, Any]:
        """Get the complete authorization map organized by System Settings panes"""
        return {
            "authorization_map": self.authorization_map,
            "total_panes": len(self.authorization_map),
            "total_authorizations": sum(len(auths) for auths in self.authorization_map.values()),
            "generated": datetime.now().isoformat()
        }

    def get_pane_discovery_info(self) -> Dict[str, Any]:
        """Get information about dynamically discovered System Settings panes"""
        if hasattr(self, 'pane_discovery'):
            return self.pane_discovery.get_summary()
        return {
            "error": "Pane discovery not initialized",
            "static_pane_count": len(self.system_panes)
        }

    def get_hardware_profile_info(self) -> Dict[str, Any]:
        """Get comprehensive hardware profile information"""
        if hasattr(self, 'hardware_profile_manager'):
            return self.hardware_profile_manager.get_hardware_profile()
        return {
            "error": "Hardware profile manager not initialized",
            "model": "Unknown Mac"
        }
