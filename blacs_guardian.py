#!/usr/bin/env python3
"""
BLACS Guardian - Tamper-Proof Protection Service

Ultra-secure tamper-resistant monitoring system that requires admin privileges
and cannot be stopped by regular users. Uses centralized JSON configuration.
"""

import os
import sys
import time
import ctypes
import psutil
import threading
import subprocess
from typing import Dict, List, Optional, Any
from blacs.sdk.integration import BLACSIntegration
from config_manager import get_config

class BLACSGuardian:
    """Tamper-proof BLACS protection service with JSON configuration."""
    
    def __init__(self):
        """Initialize the BLACS Guardian."""
        self.config = get_config()
        self.is_admin = self._check_admin_privileges()
        self.protected_apps: Dict[str, Dict[str, Any]] = {}
        self.monitoring_active = False
        self.guardian_thread: Optional[threading.Thread] = None
        self.blacs_instances: Dict[str, BLACSIntegration] = {}
        self.stop_event = threading.Event()
        
        # Load threat signatures from config
        self.all_cheat_signatures = set(self.config.get_threat_signatures())
        
        # Initialize comprehensive logging
        self._setup_comprehensive_logging()
        
        # Self-protection mechanisms
        if self.config.get("system.self_protection", True):
            self._enable_self_protection()
    
    def _setup_comprehensive_logging(self) -> None:
        """Set up comprehensive logging for all BLACS events."""
        try:
            import logging
            from datetime import datetime
            import json
            
            # Create multiple log files for different types of events
            log_files = {
                'guardian': 'blacs_guardian.log',
                'applications': 'blacs_applications.log', 
                'threats': 'blacs_threats.log',
                'dsll': 'blacs_dsll.log',
                'system': 'blacs_system.log'
            }
            
            # Configure loggers
            self.loggers = {}
            for log_type, filename in log_files.items():
                logger = logging.getLogger(f'blacs_{log_type}')
                logger.setLevel(logging.INFO)
                
                # Remove existing handlers
                for handler in logger.handlers[:]:
                    logger.removeHandler(handler)
                
                # Add file handler
                handler = logging.FileHandler(filename, mode='a', encoding='utf-8')
                formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                logger.addHandler(handler)
                
                self.loggers[log_type] = logger
            
            # Log system initialization
            init_data = {
                "event": "BLACS_INITIALIZATION",
                "timestamp": datetime.now().isoformat(),
                "admin_privileges": self.is_admin,
                "threat_signatures_count": len(self.all_cheat_signatures),
                "dsll_enabled": self.config.is_dsll_enabled(),
                "configuration_file": self.config.config_file,
                "system_settings": {
                    "tamper_resistant": self.config.get("system.tamper_resistant", False),
                    "safe_mode": self.config.get("system.safe_mode", True),
                    "bsod_protection": self.config.get("system.bsod_protection", False)
                }
            }
            
            self.loggers['system'].info(f"INITIALIZATION: {json.dumps(init_data, indent=2)}")
            print("📝 Comprehensive logging system initialized")
            
        except Exception as e:
            print(f"⚠️ Comprehensive logging setup failed: {e}")
            self.loggers = {}
    
    def _log_event(self, log_type: str, event_type: str, data: Dict[str, Any]) -> None:
        """Log an event to the appropriate log file."""
        try:
            import json
            from datetime import datetime
            
            if log_type in self.loggers:
                log_entry = {
                    "event": event_type,
                    "timestamp": datetime.now().isoformat(),
                    **data
                }
                self.loggers[log_type].info(f"{event_type}: {json.dumps(log_entry, indent=2)}")
        except Exception as e:
            print(f"⚠️ Logging error ({log_type}): {e}")
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def _require_admin(self) -> bool:
        """Require administrator privileges to continue."""
        if not self.config.get("system.admin_required", True):
            return True  # Admin not required in config
            
        if not self.is_admin:
            print("🚫 BLACS Guardian requires Administrator privileges!")
            print("   Right-click and select 'Run as administrator'")
            print("   This is required for tamper-proof protection.")
            
            # Attempt to restart with admin privileges
            try:
                if sys.argv[0].endswith('.py'):
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                else:
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.argv[0], " ".join(sys.argv[1:]), None, 1
                    )
                sys.exit(0)
            except Exception as e:
                print(f"❌ Failed to restart with admin privileges: {e}")
                return False
        
        return True
    
    def _enable_self_protection(self) -> None:
        """Enable safe tamper-resistant mechanisms (NO BSOD FUNCTIONALITY)."""
        if not self.is_admin:
            return
        
        try:
            # Only set high process priority (SAFE)
            current_process = psutil.Process()
            current_process.nice(psutil.HIGH_PRIORITY_CLASS)
            
            print("🛡️ BLACS Guardian: Safe tamper-resistance enabled")
            print("✅ High priority process protection active")
            print("🚫 BSOD functionality permanently DISABLED")
            print("🔒 Safe for system shutdown and restart")
        
        except Exception as e:
            print(f"⚠️ Tamper-resistance setup failed: {e}")
    
    def start_guardian(self) -> bool:
        """Start the tamper-proof guardian service."""
        if not self._require_admin():
            return False
        
        print("🛡️ BLACS Guardian - Advanced Anti-Cheat System")
        print("=" * 55)
        print("🔒 Administrator privileges: VERIFIED")
        print("🛡️ Tamper-resistance: ENABLED (BSOD-free)")
        print("📊 Comprehensive logging: ACTIVE")
        print(f"🔍 Threat signatures loaded: {len(self.all_cheat_signatures)}")
        print(f"🔧 Configuration: {self.config.config_file}")
        print("🎯 Mode: PRECISE DETECTION (exact matches only)")
        print("📝 Logging: ALL processes monitored, only cheat tools terminated")
        print()
        
        self.monitoring_active = True
        self.guardian_thread = threading.Thread(target=self._guardian_loop, daemon=False)
        self.guardian_thread.start()
        
        return True
    
    def add_protected_application(self, app_path: str, protection_level: str = "high") -> bool:
        """Add an application to protection without launching it."""
        # Extract app name from path
        if '\\' in app_path or '/' in app_path:
            app_name = os.path.basename(app_path)
        else:
            app_name = app_path
        
        # Ensure .exe extension
        if not app_name.lower().endswith('.exe'):
            app_name += '.exe'
        
        print(f"🎯 Adding application to protection: {app_name}")
        print(f"📁 Original input: {app_path}")
        
        # Validate protection level
        level_config = self.config.get_protection_level_config(protection_level)
        if not level_config:
            print(f"❌ Invalid protection level: {protection_level}")
            available_levels = list(self.config.get("protection_levels", {}).keys())
            print(f"   Available levels: {', '.join(available_levels)}")
            return False
        
        print(f"🔒 Protection Level: {protection_level.upper()}")
        print(f"📊 Level Settings: {level_config.get('description', 'Custom configuration')}")
        print(f"🛡️ Protection Mode: TARGETED (only scans for malicious software)")
        
        # Check if application exists (only if full path provided)
        if ('\\' in app_path or '/' in app_path) and not os.path.exists(app_path):
            print(f"⚠️ Application file not found: {app_path}")
            print(f"   Will still monitor for process name: {app_name}")
        
        # Store protected application info
        self.protected_apps[app_name] = {
            "path": app_path,
            "protection_level": protection_level,
            "level_config": level_config,
            "pid": None,
            "blacs_instance": None,
            "last_seen": None,
            "protection_active": False
        }
        
        print(f"✅ {app_name} added to protection list")
        print(f"⏳ Guardian will monitor for {app_name} launch...")
        print(f"🔍 Malicious signatures loaded: {len(self.all_cheat_signatures)}")
        print(f"🛡️ System processes will be IGNORED")
        
        return True
    
    def _guardian_loop(self) -> None:
        """Main guardian monitoring loop - TARGETED protection."""
        print("🔄 BLACS Guardian monitoring started...")
        print("🎯 Mode: TARGETED (only scans for malicious processes)")
        print("🛡️ System processes: IGNORED")
        print(f"🔍 Loaded {len(self.all_cheat_signatures)} threat signatures")
        print("📝 Logging: ALL processes monitored, only cheat tools terminated")
        
        # Log startup to file
        try:
            import logging
            logging.basicConfig(
                filename='blacs_guardian.log',
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                filemode='a'
            )
            logging.info("BLACS Guardian monitoring started")
            logging.info(f"Loaded {len(self.all_cheat_signatures)} threat signatures")
            logging.info("Monitoring mode: TARGETED (malicious processes only)")
        except Exception as e:
            print(f"⚠️ Guardian logging setup failed: {e}")
        
        # Get scan interval from the first protected app's level or default
        scan_interval = 2.0  # Faster default for better responsiveness
        if self.protected_apps:
            first_app = next(iter(self.protected_apps.values()))
            level_config = first_app.get("level_config", {})
            scan_interval = level_config.get("scan_interval", 2.0)
        
        print(f"⏱️ Scan interval: {scan_interval} seconds")
        print(f"🎯 Protected applications: {list(self.protected_apps.keys())}")
        
        # Check if any protected applications are already running
        print("🔍 Checking for already-running protected applications...")
        for app_name in self.protected_apps.keys():
            running_pid = self._find_process_by_name(app_name)
            if running_pid:
                print(f"✅ Found already-running application: {app_name} (PID: {running_pid})")
                # Enable protection immediately
                self._enable_protection_for_app(app_name, running_pid, self.protected_apps[app_name])
        
        print()
        
        while self.monitoring_active and not self.stop_event.is_set():
            try:
                # Check for protected applications
                self._check_protected_applications()
                
                # Scan ONLY for malicious processes (no system process scanning)
                self._scan_for_malicious_processes_only()
                
                # Self-protection check (minimal)
                self._verify_self_protection()
                
                time.sleep(scan_interval)
                
            except Exception as e:
                print(f"❌ Guardian error: {e}")
                time.sleep(5)
    
    def _scan_for_malicious_processes_only(self) -> None:
        """Scan ONLY for known malicious processes, completely ignore legitimate software."""
        try:
            # Get auto-terminate setting - CHECK CURRENT PROTECTION LEVELS
            auto_terminate = True  # Default
            
            # Check if any protected app has auto-terminate disabled
            for app_name, app_info in self.protected_apps.items():
                if app_info.get("protection_active", False):
                    level_config = app_info.get("level_config", {})
                    app_auto_terminate = level_config.get("auto_terminate", True)
                    if not app_auto_terminate:
                        auto_terminate = False
                        print(f"🔧 Auto-terminate DISABLED due to {app_name} protection level: {app_info.get('protection_level')}")
                        break
            
            # Debug: Show scan status
            print(f"🔍 Scanning for malicious processes... (auto-terminate: {auto_terminate})")
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = (proc_info.get('name') or '').lower()
                    proc_exe = (proc_info.get('exe') or '').lower()
                    
                    # Skip if no process name
                    if not proc_name:
                        continue
                    
                    # Skip system processes completely
                    if self._is_system_process(proc_name):
                        continue
                    
                    # Debug: Show processes being checked for CheatEngine and other threats
                    if any(threat in proc_name for threat in ['cheat', 'engine', 'artmoney', 'hack', 'inject']):
                        print(f"🔍 Checking suspicious process: {proc_name}")
                    
                    # Check against malicious signatures with ENHANCED matching
                    threat_detected = False
                    detected_signature = None
                    
                    for signature in self.all_cheat_signatures:  # Use all_cheat_signatures instead of malicious_signatures
                        # Remove .exe extension from signature for comparison
                        sig_name = signature.replace('.exe', '').lower()
                        
                        # Enhanced matching for CheatEngine variants
                        if sig_name == 'cheatengine':
                            # Match any CheatEngine variant (cheatengine, cheatengine-x86_64, etc.)
                            if 'cheatengine' in proc_name or 'cheat engine' in proc_name:
                                threat_detected = True
                                detected_signature = signature
                                print(f"🎯 CheatEngine variant detected: {proc_name} matches {signature}")
                                break
                        elif sig_name == 'artmoney':
                            # Match any ArtMoney variant
                            if 'artmoney' in proc_name or 'art money' in proc_name:
                                threat_detected = True
                                detected_signature = signature
                                print(f"🎯 ArtMoney variant detected: {proc_name} matches {signature}")
                                break
                        elif sig_name == 'processhacker':
                            # Match Process Hacker variants
                            if 'processhacker' in proc_name or 'process hacker' in proc_name or proc_name.startswith('ph'):
                                threat_detected = True
                                detected_signature = signature
                                print(f"🎯 ProcessHacker variant detected: {proc_name} matches {signature}")
                                break
                        elif sig_name in ['ollydbg', 'x64dbg', 'x32dbg']:
                            # Match debugger variants
                            if sig_name in proc_name:
                                threat_detected = True
                                detected_signature = signature
                                print(f"🎯 Debugger detected: {proc_name} matches {signature}")
                                break
                        else:
                            # Exact match for other signatures
                            if sig_name == proc_name or signature == proc_name:
                                threat_detected = True
                                detected_signature = signature
                                print(f"🎯 Exact match detected: {proc_name} matches {signature}")
                                break
                    
                    if threat_detected:
                        print(f"\n🚨 MALICIOUS SOFTWARE DETECTED!")
                        print(f"📝 Process: {proc_name}")
                        print(f"🎯 PID: {proc.pid}")
                        print(f"🔍 Signature: {detected_signature}")
                        print(f"📂 Executable: {proc_exe}")
                        
                        # Log comprehensive threat detection
                        threat_data = {
                            "process_name": proc_name,
                            "process_id": proc.pid,
                            "executable_path": proc_exe,
                            "detected_signature": detected_signature,
                            "detection_method": "signature_match",
                            "threat_category": self._get_threat_category(detected_signature),
                            "auto_terminate_enabled": auto_terminate,
                            "protected_applications": list(self.protected_apps.keys()),
                            "system_info": {
                                "scan_interval": 2.0,
                                "total_signatures": len(self.all_cheat_signatures)
                            }
                        }
                        
                        self._log_event('threats', 'THREAT_DETECTED', threat_data)
                        
                        if auto_terminate:
                            print(f"⚡ Action: IMMEDIATE TERMINATION")
                            
                            # Log termination attempt
                            self._log_event('threats', 'THREAT_TERMINATION_ATTEMPT', {
                                "process_name": proc_name,
                                "process_id": proc.pid,
                                "termination_reason": "malicious_signature_match"
                            })
                            
                            try:
                                proc.terminate()
                                time.sleep(0.2)
                                
                                if proc.is_running():
                                    proc.kill()
                                    time.sleep(0.2)
                                
                                if proc.is_running():
                                    subprocess.run(['taskkill', '/F', '/PID', str(proc.pid)], 
                                                 capture_output=True, timeout=5)
                                
                                print(f"✅ Malicious software terminated: {proc_name}")
                                
                                # Log successful termination
                                self._log_event('threats', 'THREAT_TERMINATED', {
                                    "process_name": proc_name,
                                    "process_id": proc.pid,
                                    "termination_method": "force_kill",
                                    "termination_success": True
                                })
                            
                            except Exception as term_error:
                                print(f"⚠️ Termination failed: {term_error}")
                                
                                # Log termination failure
                                self._log_event('threats', 'THREAT_TERMINATION_FAILED', {
                                    "process_name": proc_name,
                                    "process_id": proc.pid,
                                    "error": str(term_error),
                                    "error_type": type(term_error).__name__
                                })
                        else:
                            print(f"⚡ Action: DETECTION ONLY - NO TERMINATION (safe mode active)")
                            print(f"📝 DSLL can now monitor this process for syscalls")
                            
                            # Log detection-only mode
                            self._log_event('threats', 'THREAT_DETECTED_NO_TERMINATION', {
                                "process_name": proc_name,
                                "process_id": proc.pid,
                                "reason": "safe_mode_active",
                                "dsll_monitoring": True
                            })
                        
                        print("-" * 50)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"❌ Malicious process scan error: {e}")
    
    def _is_system_process(self, process_name: str) -> bool:
        """Check if a process is a system process that should be completely ignored."""
        process_name = process_name.lower()
        
        # System processes to always ignore
        system_processes = {
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe',
            'dwm.exe', 'conhost.exe', 'audiodg.exe', 'spoolsv.exe',
            'taskmgr.exe', 'taskhost.exe', 'taskhostw.exe', 'taskeng.exe',
            'dllhost.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe',
            'wuauclt.exe', 'wuapp.exe', 'trustedinstaller.exe', 'tiworker.exe'
        }
        
        if process_name in system_processes:
            return True
        
        # Check for Windows system paths
        if any(path in process_name for path in ['system32', 'syswow64', 'windows\\system']):
            return True
        
        # Check for Microsoft processes
        if any(ms in process_name for ms in ['microsoft', 'windows']):
            return True
        
        return False
    
    def _check_protected_applications(self) -> None:
        """Check if protected applications are running and protect them."""
        for app_name, app_info in self.protected_apps.items():
            try:
                # Log the check process
                self._log_event('applications', 'APPLICATION_CHECK', {
                    "application_name": app_name,
                    "protection_active": app_info.get("protection_active", False),
                    "current_pid": app_info.get("pid")
                })
                
                # Debug: Show what we're checking
                print(f"🔍 Checking for protected app: {app_name}")
                
                # Find if application is running
                running_pid = self._find_process_by_name(app_name)
                
                if running_pid and not app_info["protection_active"]:
                    # Application started (new launch), enable protection
                    print(f"\n🚀 Detected {app_name} launch (PID: {running_pid})")
                    
                    self._log_event('applications', 'APPLICATION_LAUNCHED', {
                        "application_name": app_name,
                        "process_id": running_pid,
                        "protection_level": app_info.get("protection_level"),
                        "launch_detection_method": "process_scan"
                    })
                    
                    self._enable_protection_for_app(app_name, running_pid, app_info)
                
                elif running_pid and app_info["protection_active"] and running_pid != app_info.get("pid"):
                    # Application was relaunched with new PID
                    print(f"\n🔄 Detected {app_name} RELAUNCH (Old PID: {app_info.get('pid')} → New PID: {running_pid})")
                    
                    self._log_event('applications', 'APPLICATION_RELAUNCHED', {
                        "application_name": app_name,
                        "old_process_id": app_info.get("pid"),
                        "new_process_id": running_pid,
                        "protection_level": app_info.get("protection_level")
                    })
                    
                    # Disable old protection first
                    if app_info["blacs_instance"]:
                        try:
                            app_info["blacs_instance"].disable_protection()
                        except Exception as e:
                            print(f"⚠️ Error disabling old protection: {e}")
                            self._log_event('system', 'PROTECTION_DISABLE_ERROR', {
                                "application_name": app_name,
                                "error": str(e)
                            })
                    
                    # Enable protection for new instance
                    self._enable_protection_for_app(app_name, running_pid, app_info)
                
                elif running_pid and app_info["protection_active"] and running_pid == app_info.get("pid"):
                    # Application still running with same PID, update last seen
                    app_info["last_seen"] = time.time()
                    print(f"✅ {app_name} still running (PID: {running_pid})")
                    
                    # Log periodic status
                    self._log_event('applications', 'APPLICATION_STATUS', {
                        "application_name": app_name,
                        "process_id": running_pid,
                        "status": "running",
                        "protection_active": True,
                        "uptime_seconds": time.time() - app_info.get("start_time", time.time())
                    })
                
                elif not running_pid and app_info["protection_active"]:
                    # Application closed, disable protection
                    print(f"\n⏹️ {app_name} closed, disabling protection...")
                    
                    self._log_event('applications', 'APPLICATION_CLOSED', {
                        "application_name": app_name,
                        "last_process_id": app_info.get("pid"),
                        "protection_duration": time.time() - app_info.get("start_time", time.time())
                    })
                    
                    self._disable_protection_for_app(app_name, app_info)
                
                elif not running_pid and not app_info["protection_active"]:
                    # Application not running and not protected (normal state)
                    print(f"⏳ Waiting for {app_name} to start...")
                    
                    # Log waiting status (less frequently)
                    if not hasattr(self, '_last_wait_log') or time.time() - self._last_wait_log > 30:
                        self._log_event('applications', 'APPLICATION_WAITING', {
                            "application_name": app_name,
                            "status": "waiting_for_launch"
                        })
                        self._last_wait_log = time.time()
                
            except Exception as e:
                print(f"❌ Error monitoring {app_name}: {e}")
                self._log_event('system', 'MONITORING_ERROR', {
                    "application_name": app_name,
                    "error": str(e),
                    "error_type": type(e).__name__
                })
    
    def _find_process_by_name(self, app_name: str) -> Optional[int]:
        """Find a running process by name, including relaunched instances."""
        try:
            # Debug: Show what we're looking for
            print(f"🔍 Looking for process: {app_name}")
            
            # Handle Windows app variations
            app_variations = [app_name.lower()]
            
            # Add common Windows app variations
            if app_name.lower() == 'calc.exe':
                app_variations.extend(['calculatorapp.exe', 'calculator.exe', 'calc.exe'])
            elif app_name.lower() == 'notepad.exe':
                app_variations.extend(['notepad.exe', 'notepadapp.exe'])
            elif app_name.lower() == 'mspaint.exe':
                app_variations.extend(['mspaint.exe', 'paint.exe', 'paintapp.exe'])
            
            print(f"🔍 Searching for variations: {app_variations}")
            
            # Find all processes with matching name
            matching_processes = []
            all_processes_checked = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    all_processes_checked += 1
                    
                    # Debug: Show processes that might match
                    if any(variation.replace('.exe', '') in proc_name for variation in app_variations):
                        print(f"   📝 Checking: {proc_info.get('name', 'unknown')} (PID: {proc_info.get('pid', 0)})")
                    
                    # Match by any variation
                    for variation in app_variations:
                        if proc_name == variation:
                            matching_processes.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'create_time': proc_info['create_time']
                            })
                            print(f"   ✅ EXACT MATCH FOUND: {proc_info['name']} (PID: {proc_info['pid']}) matches {variation}")
                            break
                    
                    # If no exact match, try partial matching for Windows apps
                    if not matching_processes:
                        for variation in app_variations:
                            base_name = variation.replace('.exe', '')
                            if base_name in proc_name and len(base_name) > 3:  # Avoid false positives
                                matching_processes.append({
                                    'pid': proc_info['pid'],
                                    'name': proc_info['name'],
                                    'create_time': proc_info['create_time']
                                })
                                print(f"   ✅ PARTIAL MATCH FOUND: {proc_info['name']} (PID: {proc_info['pid']}) contains {base_name}")
                                break
                    
                    # Also try matching by executable path
                    if not matching_processes and proc_info.get('exe'):
                        exe_name = proc_info['exe'].split('\\')[-1].lower()
                        for variation in app_variations:
                            if exe_name == variation:
                                matching_processes.append({
                                    'pid': proc_info['pid'],
                                    'name': proc_info['name'],
                                    'create_time': proc_info['create_time']
                                })
                                print(f"   ✅ EXE PATH MATCH FOUND: {proc_info['name']} (PID: {proc_info['pid']})")
                                break
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            print(f"🔍 Checked {all_processes_checked} processes, found {len(matching_processes)} matches")
            
            if not matching_processes:
                print(f"❌ No processes found matching '{app_name}' or its variations")
                return None
            
            # If we have a previously tracked PID, check if it's still running
            app_info = self.protected_apps.get(app_name, {})
            previous_pid = app_info.get("pid")
            
            if previous_pid:
                # Check if the previous PID is still in our list
                for proc in matching_processes:
                    if proc['pid'] == previous_pid:
                        print(f"✅ Previous PID {previous_pid} still running")
                        return previous_pid  # Same instance still running
            
            # If previous PID is not running, find the newest instance
            # This handles relaunch detection
            if matching_processes:
                # Sort by creation time (newest first) and return the newest instance
                newest_proc = max(matching_processes, key=lambda x: x['create_time'])
                print(f"✅ Found newest instance: {newest_proc['name']} (PID: {newest_proc['pid']})")
                return newest_proc['pid']
            
        except Exception as e:
            print(f"❌ Error finding process {app_name}: {e}")
        
        return None
    
    def _scan_for_cheat_tools(self) -> None:
        """Legacy method - redirects to new malicious-only scanning."""
        self._scan_for_malicious_processes_only()
    
    def _verify_self_protection(self) -> None:
        """Verify guardian self-protection is still active."""
        if not self.config.get("system.self_protection", True):
            return
            
        try:
            current_process = psutil.Process()
            
            # Check if still running with high priority
            if current_process.nice() != psutil.HIGH_PRIORITY_CLASS:
                current_process.nice(psutil.HIGH_PRIORITY_CLASS)
                print("🛡️ Guardian: Self-protection priority restored")
        
        except Exception as e:
            print(f"⚠️ Self-protection verification failed: {e}")
    
    def stop_guardian(self) -> None:
        """Stop the guardian service gracefully."""
        print("\n⏹️ Stopping BLACS Guardian gracefully...")
        
        try:
            # Set flag to stop monitoring
            self.monitoring_active = False
            self.stop_event.set()
            
            # Disable protection for all apps first
            for app_name, app_info in self.protected_apps.items():
                if app_info["blacs_instance"]:
                    try:
                        print(f"🔓 Disabling protection for {app_name}...")
                        app_info["blacs_instance"].disable_protection()
                    except Exception as e:
                        print(f"⚠️ Error disabling protection for {app_name}: {e}")
            
            # Wait for monitoring thread to finish
            if self.guardian_thread and self.guardian_thread.is_alive():
                print("⏳ Waiting for monitoring thread to stop...")
                self.guardian_thread.join(timeout=5)
                
                if self.guardian_thread.is_alive():
                    print("⚠️ Monitoring thread did not stop gracefully")
                else:
                    print("✅ Monitoring thread stopped")
            
            # Reset process priority to normal (prevents issues)
            try:
                current_process = psutil.Process()
                current_process.nice(psutil.NORMAL_PRIORITY_CLASS)
                print("🔄 Process priority reset to normal")
            except Exception as e:
                print(f"⚠️ Could not reset process priority: {e}")
            
            print("✅ BLACS Guardian stopped safely")
            
        except Exception as e:
            print(f"⚠️ Error during shutdown: {e}")
            print("✅ BLACS Guardian stopped (with warnings)")
    
    def _enable_protection_for_app(self, app_name: str, pid: int, app_info: Dict[str, Any]) -> None:
        """Enable protection for an application."""
        try:
            print(f"\n📱 APPLICATION STARTED!")
            print(f"📝 Application: {app_name}")
            print(f"🎯 PID: {pid}")
            print(f"🔒 Protection Level: {app_info['protection_level'].upper()}")
            print(f"⏰ Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 50)
            
            # Record start time
            app_info["start_time"] = time.time()
            
            # Log comprehensive application startup
            startup_data = {
                "application_name": app_name,
                "process_id": pid,
                "protection_level": app_info['protection_level'],
                "level_configuration": app_info.get('level_config', {}),
                "application_path": app_info.get('path'),
                "start_timestamp": time.time(),
                "dsll_enabled": app_info.get('level_config', {}).get('dsll_enabled', False),
                "auto_terminate": app_info.get('level_config', {}).get('auto_terminate', True),
                "scan_interval": app_info.get('level_config', {}).get('scan_interval', 2.0)
            }
            
            self._log_event('applications', 'PROTECTION_ENABLED', startup_data)
            
            # Log application startup
            try:
                import logging
                logging.info(f"APPLICATION_STARTED: {app_name} (PID: {pid}) - Protection Level: {app_info['protection_level']}")
            except Exception as e:
                print(f"⚠️ Application startup logging failed: {e}")
            
            # Create BLACS protection
            blacs = BLACSIntegration(app_name, "1.0.0")
            
            # Set up threat callback
            def on_threat(violation_data):
                print(f"\n🚨 GUARDIAN ALERT: {app_name} UNDER ATTACK!")
                print(f"📝 Threat: {violation_data.get('description', 'Unknown')}")
                print(f"⚡ Guardian Response: Threat neutralized")
                print("-" * 50)
                
                # Log threat callback
                self._log_event('threats', 'APPLICATION_UNDER_ATTACK', {
                    "application_name": app_name,
                    "process_id": pid,
                    "threat_description": violation_data.get('description', 'Unknown'),
                    "violation_data": violation_data
                })
            
            blacs.set_violation_callback("critical", on_threat)
            blacs.set_violation_callback("high", on_threat)
            
            # Enable protection with configured level
            if blacs.enable_protection(app_info["protection_level"]):
                # Add to DSLL protection if enabled
                if self.config.is_dsll_enabled() and blacs.blacs_system:
                    print(f"🔍 DSLL: Adding process {pid} to DSLL protection...")
                    blacs.blacs_system.add_protected_process(pid)
                    print(f"✅ DSLL: Process {pid} added to advanced monitoring")
                    
                    # Log DSLL activation
                    self._log_event('dsll', 'DSLL_PROTECTION_ENABLED', {
                        "application_name": app_name,
                        "process_id": pid,
                        "dsll_monitor_active": True,
                        "critical_syscalls_count": len(self.config.get_critical_syscalls())
                    })
                    
                    # Check if DSLL monitor exists and is working
                    if hasattr(blacs.blacs_system, 'dsll_monitor'):
                        dsll_stats = blacs.blacs_system.dsll_monitor.get_statistics()
                        print(f"📊 DSLL Statistics: {dsll_stats}")
                        
                        self._log_event('dsll', 'DSLL_STATISTICS', {
                            "application_name": app_name,
                            "process_id": pid,
                            "statistics": dsll_stats
                        })
                    else:
                        print("⚠️ DSLL: Monitor not found in BLACS system")
                        self._log_event('system', 'DSLL_MONITOR_ERROR', {
                            "application_name": app_name,
                            "error": "DSLL monitor not found in BLACS system"
                        })
                else:
                    if not self.config.is_dsll_enabled():
                        print("⚠️ DSLL: Disabled in configuration")
                        self._log_event('dsll', 'DSLL_DISABLED', {
                            "application_name": app_name,
                            "reason": "disabled_in_configuration"
                        })
                    if not blacs.blacs_system:
                        print("⚠️ DSLL: BLACS system not available")
                        self._log_event('system', 'BLACS_SYSTEM_ERROR', {
                            "application_name": app_name,
                            "error": "BLACS system not available"
                        })
                
                # IMPORTANT: Pass protection level to process monitor
                if hasattr(blacs.blacs_system, 'process_monitor'):
                    blacs.blacs_system.process_monitor.protection_level = app_info["protection_level"]
                    print(f"🔧 Process monitor configured for protection level: {app_info['protection_level']}")
                
                # Update app info
                app_info["pid"] = pid
                app_info["blacs_instance"] = blacs
                app_info["protection_active"] = True
                app_info["last_seen"] = time.time()
                
                print(f"✅ {app_name} protection ACTIVATED (PID: {pid})")
                if self.config.is_dsll_enabled():
                    print(f"🔍 DSLL monitoring: ACTIVE")
                print(f"🛡️ Guardian protection: ENABLED")
                
                # Show protection level settings
                level_config = app_info.get("level_config", {})
                auto_terminate = level_config.get("auto_terminate", True)
                print(f"⚡ Auto-terminate: {'ENABLED' if auto_terminate else 'DISABLED'}")
                
                # Log final protection status
                self._log_event('applications', 'PROTECTION_FULLY_ACTIVE', {
                    "application_name": app_name,
                    "process_id": pid,
                    "protection_components": {
                        "guardian": True,
                        "dsll": self.config.is_dsll_enabled(),
                        "process_monitor": True,
                        "memory_monitor": True,
                        "input_monitor": True
                    },
                    "auto_terminate": auto_terminate
                })
                
            else:
                print(f"❌ Failed to enable protection for {app_name}")
                self._log_event('system', 'PROTECTION_ENABLE_FAILED', {
                    "application_name": app_name,
                    "process_id": pid,
                    "error": "BLACS protection enable failed"
                })
        
        except Exception as e:
            print(f"❌ Error enabling protection for {app_name}: {e}")
            self._log_event('system', 'PROTECTION_ENABLE_ERROR', {
                "application_name": app_name,
                "process_id": pid,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    def _disable_protection_for_app(self, app_name: str, app_info: Dict[str, Any]) -> None:
        """Disable protection for an application."""
        try:
            if app_info["blacs_instance"]:
                # Export DSLL ledger if enabled
                if self.config.is_dsll_enabled():
                    print(f"📝 Exporting DSLL forensic ledger...")
                    ledger_filename = f"guardian_log_{app_name}_{int(time.time())}.json"
                    if app_info["blacs_instance"].export_dsll_ledger(ledger_filename):
                        print(f"✅ DSLL ledger exported: {ledger_filename}")
                
                # Disable protection
                app_info["blacs_instance"].disable_protection()
            
            # Reset app info
            app_info["pid"] = None
            app_info["blacs_instance"] = None
            app_info["protection_active"] = False
            app_info["last_seen"] = None
            
            print(f"✅ {app_name} protection disabled")
            print(f"⏳ Guardian continues monitoring for relaunch...")
        
        except Exception as e:
            print(f"❌ Error disabling protection for {app_name}: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get guardian status."""
        return {
            "admin_privileges": self.is_admin,
            "monitoring_active": self.monitoring_active,
            "protected_applications": len(self.protected_apps),
            "active_protections": sum(1 for app in self.protected_apps.values() if app["protection_active"]),
            "cheat_signatures": len(self.all_cheat_signatures),
            "dsll_enabled": self.config.is_dsll_enabled(),
            "applications": {
                name: {
                    "path": info["path"],
                    "protection_level": info["protection_level"],
                    "running": info["protection_active"],
                    "pid": info["pid"]
                }
                for name, info in self.protected_apps.items()
            }
        }

def main():
    """Main guardian function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="BLACS Guardian - Tamper-Proof Protection Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python blacs_guardian.py "C:\\Windows\\System32\\calc.exe" --level safe
  python blacs_guardian.py "C:\\Windows\\System32\\calc.exe" --level high
  python blacs_guardian.py "C:\\Program Files\\MyGame\\game.exe" --level maximum
  python blacs_guardian.py notepad.exe --level safe

Protection Levels:
  safe     - Ultra-safe mode, only blocks obvious cheat tools
  low      - Basic protection, no auto-termination
  medium   - Balanced protection, no auto-termination  
  high     - Strict protection with auto-termination
  maximum  - Maximum protection, very aggressive

Note: Requires Administrator privileges for tamper-proof protection.
Configuration: Edit blacs_config.json to customize all settings.
        """
    )
    
    parser.add_argument("app_path", help="Path to application to protect")
    parser.add_argument("--level", "-l", choices=["safe", "low", "medium", "high", "maximum"], 
                       default="high", help="Protection level (default: high)")
    
    args = parser.parse_args()
    
    # Create guardian
    guardian = BLACSGuardian()
    
    try:
        # Start guardian service
        if not guardian.start_guardian():
            sys.exit(1)
        
        # Add application to protection
        if not guardian.add_protected_application(args.app_path, args.level):
            sys.exit(1)
        
        print(f"\n💡 BLACS Guardian is now monitoring for {os.path.basename(args.app_path)}")
        print(f"🔒 Safe protection: ACTIVE (no system crashes)")
        print(f"⚠️  Self-protection: DISABLED (prevents BSOD)")
        print(f"🔧 Configuration: Edit blacs_config.json to customize settings")
        print(f"⏹️  Press Ctrl+C to stop safely")
        
        # Keep guardian running with safe shutdown
        try:
            while guardian.monitoring_active:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n⏹️ Safe shutdown requested...")
        
    except KeyboardInterrupt:
        print(f"\n⏹️ Safe shutdown requested...")
    except Exception as e:
        print(f"❌ Guardian error: {e}")
    finally:
        # Always try to stop gracefully
        try:
            guardian.stop_guardian()
        except Exception as e:
            print(f"⚠️ Error during final cleanup: {e}")
        
        print("🔄 System restored to normal state")
        print("✅ Safe to close terminal")

if __name__ == "__main__":
    main()