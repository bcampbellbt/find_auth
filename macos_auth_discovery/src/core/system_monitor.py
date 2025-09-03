#!/usr/bin/env python3
"""
System Level Monitor
Handles system-level authorization detection using Security.framework APIs
"""

import logging
import threading
import time
import subprocess
import json
from typing import Dict, List, Optional, Callable
from datetime import datetime

try:
    import objc
    from Security import *
    from Foundation import *
    HAS_SECURITY_FRAMEWORK = True
except ImportError:
    HAS_SECURITY_FRAMEWORK = False

class AuthorizationEvent:
    """Represents an authorization event"""
    
    def __init__(self, right_name: str, right_description: str = "", 
                 context: str = "", result: str = "", timestamp: datetime = None):
        self.right_name = right_name
        self.right_description = right_description
        self.context = context
        self.result = result
        self.timestamp = timestamp or datetime.now()
        self.metadata = {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'right_name': self.right_name,
            'right_description': self.right_description,
            'context': self.context,
            'result': self.result,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }

class SystemLevelMonitor:
    """System-level authorization monitoring using Security.framework"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_monitoring = False
        self.authorization_events = []
        self.event_callbacks = []
        self.monitor_thread = None
        self.known_rights = {}
        
        # Initialize authorization database knowledge
        self._load_known_authorization_rights()
    
    def _load_known_authorization_rights(self):
        """Load known authorization rights and their descriptions"""
        # Common macOS authorization rights relevant to EPM
        self.known_rights = {
            # System Preferences / System Settings
            'system.preferences': 'Access System Preferences',
            'system.preferences.security': 'Modify Security & Privacy settings',
            'system.preferences.sharing': 'Modify Sharing settings',
            'system.preferences.users': 'Modify Users & Groups settings',
            'system.preferences.datetime': 'Modify Date & Time settings',
            'system.preferences.network': 'Modify Network settings',
            'system.preferences.energysaver': 'Modify Energy Saver settings',
            
            # Privacy and Security
            'system.privilege.admin': 'Administrator privileges required',
            'system.privilege.taskport': 'Task port access',
            'system.install.software': 'Install software',
            'system.install.software.iboot': 'Install boot software',
            
            # Kernel Extensions and System Extensions
            'com.apple.KernelExtensionManagement': 'Kernel Extension Management',
            'com.apple.SystemExtensions': 'System Extensions Management',
            
            # Privacy Framework (TCC)
            'kTCCServiceAccessibility': 'Accessibility access',
            'kTCCServiceCamera': 'Camera access',
            'kTCCServiceMicrophone': 'Microphone access',
            'kTCCServiceScreenCapture': 'Screen recording access',
            'kTCCServiceSystemPolicyAllFiles': 'Full disk access',
            'kTCCServiceDeveloperTool': 'Developer tool access',
            
            # Authentication and Authorization
            'authenticate-admin': 'Administrator authentication',
            'authenticate-session-owner': 'Session owner authentication',
            'authenticate-session-user': 'Session user authentication',
        }
    
    def start_monitoring(self):
        """Start system-level authorization monitoring"""
        if self.is_monitoring:
            self.logger.warning("Monitoring already started")
            return
        
        self.is_monitoring = True
        self.logger.info("Starting system-level authorization monitoring")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop system-level authorization monitoring"""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        self.logger.info("Stopping system-level authorization monitoring")
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Check for authorization events
                self._check_authorization_database()
                self._monitor_security_events()
                time.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1.0)
    
    def _check_authorization_database(self):
        """Check authorization database for new rights"""
        try:
            if not HAS_SECURITY_FRAMEWORK:
                return
            
            # This would use Security.framework APIs to monitor authorization requests
            # For now, we'll use a fallback approach
            self._fallback_authorization_check()
            
        except Exception as e:
            self.logger.error(f"Error checking authorization database: {e}")
    
    def _fallback_authorization_check(self):
        """Fallback method using system tools to detect authorization events"""
        try:
            # Monitor system log for authorization-related events
            result = subprocess.run([
                'log', 'show', '--last', '1s', '--predicate', 
                'process == "authd" OR process == "SecurityAgent" OR process == "tccd"',
                '--style', 'ndjson'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            log_entry = json.loads(line)
                            self._process_log_entry(log_entry)
                        except json.JSONDecodeError:
                            continue
                            
        except subprocess.TimeoutExpired:
            pass  # Timeout is expected for continuous monitoring
        except Exception as e:
            self.logger.debug(f"Fallback authorization check error: {e}")
    
    def _process_log_entry(self, log_entry: Dict):
        """Process a log entry for authorization events"""
        try:
            message = log_entry.get('eventMessage', '')
            process = log_entry.get('processImagePath', '')
            
            # Look for authorization-related keywords
            auth_keywords = [
                'authorization', 'authenticate', 'privilege', 'right',
                'SecurityAgent', 'authd', 'tccd', 'kext', 'system extension'
            ]
            
            if any(keyword in message.lower() for keyword in auth_keywords):
                event = AuthorizationEvent(
                    right_name=self._extract_right_name(message),
                    right_description=self._get_right_description(message),
                    context=f"Process: {process}",
                    result="detected",
                    timestamp=datetime.now()
                )
                
                event.metadata = {
                    'process': process,
                    'message': message,
                    'source': 'system_log'
                }
                
                self._add_authorization_event(event)
                
        except Exception as e:
            self.logger.debug(f"Error processing log entry: {e}")
    
    def _extract_right_name(self, message: str) -> str:
        """Extract authorization right name from log message"""
        # Simple extraction - could be enhanced with regex patterns
        for right in self.known_rights.keys():
            if right in message:
                return right
        
        # Look for common patterns
        import re
        patterns = [
            r'right\s*[\'"]([^\'"]+)[\'"]',
            r'privilege\s*[\'"]([^\'"]+)[\'"]',
            r'authorization\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "unknown_authorization"
    
    def _get_right_description(self, message: str) -> str:
        """Get description for authorization right"""
        right_name = self._extract_right_name(message)
        return self.known_rights.get(right_name, "Unknown authorization right")
    
    def _monitor_security_events(self):
        """Monitor for security-related events"""
        try:
            # Monitor for TCC (Privacy) events
            self._monitor_tcc_events()
            
            # Monitor for system policy events
            self._monitor_system_policy_events()
            
        except Exception as e:
            self.logger.debug(f"Error monitoring security events: {e}")
    
    def _monitor_tcc_events(self):
        """Monitor TCC (Transparency, Consent, and Control) events"""
        try:
            # TCC database is typically at /Library/Application Support/com.apple.TCC/TCC.db
            # For now, we'll monitor tccd process logs
            result = subprocess.run([
                'log', 'show', '--last', '1s', '--predicate', 'process == "tccd"',
                '--style', 'ndjson'
            ], capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            log_entry = json.loads(line)
                            message = log_entry.get('eventMessage', '')
                            
                            if any(service in message for service in [
                                'kTCCService', 'accessibility', 'camera', 'microphone',
                                'screen', 'full disk', 'developer'
                            ]):
                                event = AuthorizationEvent(
                                    right_name="TCC_Privacy_Request",
                                    right_description="Privacy permission request",
                                    context="TCC Framework",
                                    result="detected"
                                )
                                event.metadata = {'tcc_message': message, 'source': 'tccd'}
                                self._add_authorization_event(event)
                                
                        except json.JSONDecodeError:
                            continue
                            
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.logger.debug(f"TCC monitoring error: {e}")
    
    def _monitor_system_policy_events(self):
        """Monitor system policy authorization events"""
        try:
            # Monitor for system policy changes
            result = subprocess.run([
                'log', 'show', '--last', '1s', '--predicate', 
                'category == "SystemPolicy" OR subsystem CONTAINS "security"',
                '--style', 'ndjson'
            ], capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            log_entry = json.loads(line)
                            message = log_entry.get('eventMessage', '')
                            
                            if 'authorization' in message.lower() or 'policy' in message.lower():
                                event = AuthorizationEvent(
                                    right_name="SystemPolicy_Change",
                                    right_description="System policy authorization",
                                    context="System Policy",
                                    result="detected"
                                )
                                event.metadata = {'policy_message': message, 'source': 'system_policy'}
                                self._add_authorization_event(event)
                                
                        except json.JSONDecodeError:
                            continue
                            
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.logger.debug(f"System policy monitoring error: {e}")
    
    def _add_authorization_event(self, event: AuthorizationEvent):
        """Add authorization event to the list"""
        # Avoid duplicates
        if not any(e.right_name == event.right_name and 
                  abs((e.timestamp - event.timestamp).total_seconds()) < 1 
                  for e in self.authorization_events[-10:]):  # Check last 10 events
            
            self.authorization_events.append(event)
            self.logger.info(f"Authorization event detected: {event.right_name}")
            
            # Notify callbacks
            for callback in self.event_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    self.logger.error(f"Error in event callback: {e}")
    
    def add_event_callback(self, callback: Callable[[AuthorizationEvent], None]):
        """Add callback for authorization events"""
        self.event_callbacks.append(callback)
    
    def get_authorization_events(self) -> List[AuthorizationEvent]:
        """Get all detected authorization events"""
        return self.authorization_events.copy()
    
    def clear_events(self):
        """Clear all authorization events"""
        self.authorization_events.clear()
        self.logger.info("Authorization events cleared")
    
    def get_events_since(self, timestamp: datetime) -> List[AuthorizationEvent]:
        """Get authorization events since a specific timestamp"""
        return [event for event in self.authorization_events 
                if event.timestamp >= timestamp]
    
    def simulate_authorization_trigger(self, setting_path: str):
        """Simulate triggering an authorization for testing purposes"""
        # This method would be called when the discovery engine
        # interacts with a setting that should trigger authorization
        self.logger.debug(f"Monitoring for authorization triggered by: {setting_path}")
        
        # Create a test event for demonstration
        if "security" in setting_path.lower() or "privacy" in setting_path.lower():
            event = AuthorizationEvent(
                right_name="system.preferences.security",
                right_description="Security & Privacy settings access",
                context=f"System Settings: {setting_path}",
                result="simulated"
            )
            event.metadata = {
                'trigger_path': setting_path,
                'source': 'ui_simulation'
            }
            self._add_authorization_event(event)
    
    def get_summary_stats(self) -> Dict:
        """Get summary statistics of detected authorizations"""
        total_events = len(self.authorization_events)
        unique_rights = len(set(event.right_name for event in self.authorization_events))
        
        return {
            'total_events': total_events,
            'unique_rights': unique_rights,
            'events_last_hour': len([
                event for event in self.authorization_events
                if (datetime.now() - event.timestamp).total_seconds() < 3600
            ]),
            'most_common_rights': self._get_most_common_rights()
        }
    
    def _get_most_common_rights(self) -> List[Dict[str, int]]:
        """Get most commonly detected authorization rights"""
        from collections import Counter
        
        right_counts = Counter(event.right_name for event in self.authorization_events)
        return [{'right': right, 'count': count} 
                for right, count in right_counts.most_common(10)]
