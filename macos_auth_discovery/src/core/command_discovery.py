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

class CommandDiscoveryEngine:
    """Discovers system authorization requirements using comprehensive system analysis"""
    
    def __init__(self, no_sudo=False):
        self.logger = logging.getLogger(__name__)
        self.discovery_results = []
        self.is_running = False
        self.progress = 0
        self.no_sudo = no_sudo
        self.total_checks = 15  # Total number of discovery categories
        self.current_check = 0
        if no_sudo:
            self.logger.info("Running in no-sudo mode - some checks may be skipped")
        
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
        self.progress = int((self.current_check / self.total_checks) * 100)
        self.logger.info(f"Checking {category} ({self.current_check}/{self.total_checks})...")

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

    def discover_all_authorizations(self) -> List[Dict[str, Any]]:
        """Run comprehensive authorization discovery"""
        self.logger.info("Starting comprehensive macOS authorization discovery...")
        self.is_running = True
        self.progress = 0
        self.current_check = 0
        self.discovery_results = []
        
        try:
            # Run all discovery methods
            discovery_methods = [
                self._check_tcc_database,
                self._check_security_framework,
                self._check_network_security,
                self._check_user_accounts,
                self._check_keychain_access,
                self._check_system_preferences_auth,
                self._check_developer_tools
            ]
            
            for method in discovery_methods:
                try:
                    results = method()
                    self.discovery_results.extend(results)
                except Exception as e:
                    self.logger.error(f"Error in {method.__name__}: {e}")
            
            self.progress = 100
            self.logger.info(f"Discovery complete. Found {len(self.discovery_results)} authorization points.")
            
        except Exception as e:
            self.logger.error(f"Discovery error: {e}")
        finally:
            self.is_running = False
            
        return self.discovery_results

    def get_progress(self) -> int:
        """Get current discovery progress percentage"""
        return self.progress

    def is_discovery_running(self) -> bool:
        """Check if discovery is currently running"""
        return self.is_running

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
