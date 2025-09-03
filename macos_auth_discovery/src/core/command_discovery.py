#!/usr/bin/env python3
"""
Command-based Authorization Discovery Engine
Discovers authorization requirements using system commands and file inspection
"""

import logging
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class CommandDiscoveryEngine:
    """Discovers system authorization requirements using command-line tools"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.discovery_results = []
        self.is_running = False
        self.progress = 0
        
    def _run_command(self, command: str) -> tuple[int, str, str]:
        """Run a shell command and return exit code, stdout, stderr"""
        try:
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )
            return process.returncode, process.stdout, process.stderr
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            return 1, "", str(e)

    def _check_tcc_database(self) -> List[Dict[str, Any]]:
        """Check TCC.db for privacy-sensitive permissions"""
        tcc_paths = [
            "/Library/Application Support/com.apple.TCC/TCC.db",
            "~/Library/Application Support/com.apple.TCC/TCC.db"
        ]
        auth_entries = []
        
        for db_path in tcc_paths:
            code, stdout, stderr = self._run_command(f"sqlite3 {db_path} 'SELECT client,service FROM access' 2>/dev/null")
            if code == 0 and stdout:
                for line in stdout.splitlines():
                    if '|' in line:
                        client, service = line.split('|')
                        auth_entries.append({
                            "type": "privacy",
                            "category": "TCC Permission",
                            "service": service,
                            "client": client,
                            "source": db_path
                        })
        
        return auth_entries

    def discover_security_auth(self) -> List[Dict[str, Any]]:
        """Discover security and authentication settings"""
        auth_points = []
        
        # Check FileVault status
        code, stdout, stderr = self._run_command("fdesetup status")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "FileVault",
                "status": "enabled" if "FileVault is On" in stdout else "disabled",
                "requires_auth": True,
                "auth_type": "admin",
                "description": "Full disk encryption requires authentication for setup and recovery"
            })

        # Check firmware password status
        code, stdout, stderr = self._run_command("sudo /usr/sbin/firmwarepasswd -check 2>/dev/null")
        if code == 0:
            auth_points.append({
                "type": "security",
                "category": "Firmware Password",
                "status": "enabled" if "Yes" in stdout else "disabled",
                "requires_auth": True,
                "auth_type": "firmware_password",
                "description": "Firmware password protects against unauthorized system access"
            })

        return auth_points

    def discover_system_auth(self) -> List[Dict[str, Any]]:
        """Discover system-level authorization requirements"""
        auth_points = []
        
        # System software updates
        code, stdout, stderr = self._run_command("softwareupdate --schedule")
        auth_points.append({
            "type": "system",
            "category": "Software Update",
            "requires_auth": True,
            "auth_type": "admin",
            "description": "Installing system updates requires administrator authentication"
        })

        # Check Time Machine backup encryption
        code, stdout, stderr = self._run_command("tmutil destinationinfo 2>/dev/null | grep -i 'encrypted'")
        if code == 0:
            auth_points.append({
                "type": "system",
                "category": "Time Machine",
                "requires_auth": True,
                "auth_type": "user",
                "description": "Time Machine backup encryption requires password for access"
            })

        return auth_points

    def discover_network_auth(self) -> List[Dict[str, Any]]:
        """Discover network-related authorization requirements"""
        auth_points = []
        
        # Check firewall status
        code, stdout, stderr = self._run_command("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
        auth_points.append({
            "type": "network",
            "category": "Firewall",
            "requires_auth": True,
            "auth_type": "admin",
            "description": "Modifying firewall settings requires administrator authentication"
        })

        # Check network service modifications
        auth_points.append({
            "type": "network",
            "category": "Network Settings",
            "requires_auth": True,
            "auth_type": "admin",
            "description": "Modifying network services requires administrator authentication"
        })

        return auth_points

    def start_discovery(self) -> Dict[str, Any]:
        """Start the authorization discovery process"""
        self.logger.info("Starting command-based authorization discovery")
        self.is_running = True
        self.progress = 0
        start_time = datetime.now()

        try:
            # Collect authorization data from different areas
            auth_data = {
                "security": self.discover_security_auth(),
                "system": self.discover_system_auth(),
                "network": self.discover_network_auth(),
                "privacy": self._check_tcc_database()
            }

            # Create discovery report
            report = {
                "discovery_session": {
                    "start_time": start_time.isoformat(),
                    "end_time": datetime.now().isoformat(),
                    "duration_seconds": (datetime.now() - start_time).total_seconds()
                },
                "authorization_results": auth_data
            }

            # Save report
            report_path = Path("data") / f"auth_discovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report_path.parent.mkdir(exist_ok=True)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)

            self.logger.info(f"Discovery report saved to: {report_path}")
            return report

        except Exception as e:
            self.logger.error(f"Discovery error: {e}")
            return {"error": str(e)}
        finally:
            self.is_running = False
            self.progress = 100

    def get_progress(self) -> Dict[str, Any]:
        """Get current discovery progress"""
        return {
            "is_running": self.is_running,
            "progress_percent": self.progress
        }
