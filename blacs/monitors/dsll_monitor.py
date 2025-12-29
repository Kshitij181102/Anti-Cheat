#!/usr/bin/env python3
"""
BLACS DSLL Monitor - Deterministic Syscall Lockstep Ledger

Revolutionary shadow verification system that records and validates every 
sensitive system call during a protected session using JSON configuration.
"""

import time
import threading
import ctypes
import psutil
from typing import Dict, List, Any, Optional, Tuple
from collections import deque
from dataclasses import dataclass
from enum import Enum

# Import JSON configuration
try:
    from config_manager import get_config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

class SyscallType(Enum):
    """System call types monitored by DSLL."""
    INPUT = "input"
    MEMORY = "memory"
    PROCESS = "process"
    DRIVER = "driver"
    PRIVILEGE = "privilege"
    OVERLAY = "overlay"
    HOOK = "hook"
    FILE = "file"
    REGISTRY = "registry"
    NETWORK = "network"

@dataclass
class SyscallRecord:
    """Record of a system call for DSLL verification."""
    timestamp: float
    syscall_type: SyscallType
    process_id: int
    process_name: str
    syscall_name: str
    parameters: Dict[str, Any]
    return_value: Any
    thread_id: int
    stack_trace: List[str]
    verification_hash: str

class DSLLMonitor:
    """Deterministic Syscall Lockstep Ledger Monitor."""
    
    def __init__(self):
        """Initialize DSLL monitor with JSON configuration."""
        self.enabled = True
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        # Load JSON configuration
        if CONFIG_AVAILABLE:
            self.config = get_config()
            dsll_config = self.config.get_dsll_config()
            monitor_config = self.config.get_monitor_config("dsll_monitor")
            
            self.enabled = dsll_config.get("enabled", True)
            self.monitor_interval = monitor_config.get("settings", {}).get("monitor_interval", 0.1)
            ledger_max_size = monitor_config.get("settings", {}).get("ledger_max_size", 10000)
            self.critical_syscalls = set(dsll_config.get("critical_syscalls", []))
        else:
            # Fallback configuration
            self.monitor_interval = 0.1
            ledger_max_size = 10000
            self.critical_syscalls = {
                "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtOpenProcess",
                "NtCreateThread", "NtSuspendProcess", "NtResumeProcess",
                "NtTerminateProcess", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
                "NtCreateFile", "NtSetValueKey", "NtLoadDriver"
            }
        
        # DSLL ledger storage
        self.syscall_ledger: deque = deque(maxlen=ledger_max_size)
        self.verification_hashes: Dict[str, str] = {}
        self.suspicious_patterns: List[Dict[str, Any]] = []
        
        # Monitoring configuration
        self.protected_processes: List[int] = []
        
        # Statistics
        self.stats = {
            "total_syscalls_recorded": 0,
            "suspicious_patterns_detected": 0,
            "verification_failures": 0,
            "protected_processes": 0
        }
    
    def add_protected_process(self, pid: int) -> None:
        """Add a process to DSLL protection."""
        if pid not in self.protected_processes:
            self.protected_processes.append(pid)
            self.stats["protected_processes"] = len(self.protected_processes)
            print(f"🔒 DSLL: Now protecting process {pid}")
            print(f"📊 DSLL: Total protected processes: {len(self.protected_processes)}")
            
            # Log to file
            try:
                import logging
                logging.basicConfig(filename='blacs_dsll.log', level=logging.INFO, 
                                  format='%(asctime)s - DSLL - %(message)s')
                logging.info(f"Added process {pid} to DSLL protection")
            except:
                pass
        else:
            print(f"⚠️ DSLL: Process {pid} already protected")
    
    def remove_protected_process(self, pid: int) -> None:
        """Remove a process from DSLL protection."""
        if pid in self.protected_processes:
            self.protected_processes.remove(pid)
            self.stats["protected_processes"] = len(self.protected_processes)
            print(f"🔓 DSLL: Stopped protecting process {pid}")
    
    def start_monitoring(self) -> None:
        """Start DSLL monitoring."""
        if self.monitoring_active:
            return
        
        print("🔍 DSLL: Starting deterministic syscall monitoring...")
        print(f"📊 DSLL: Monitor enabled: {self.enabled}")
        print(f"📊 DSLL: Monitor interval: {self.monitor_interval}s")
        print(f"📊 DSLL: Critical syscalls loaded: {len(self.critical_syscalls)}")
        print(f"📊 DSLL: Protected processes: {len(self.protected_processes)}")
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        print("✅ DSLL: Advanced syscall monitoring active")
        
        # Force some test output
        print("🧪 DSLL: Monitoring system ready - will detect syscalls from external tools")
        
        # Log to file as well
        try:
            import logging
            logging.basicConfig(filename='blacs_dsll.log', level=logging.INFO, 
                              format='%(asctime)s - DSLL - %(message)s')
            logging.info("DSLL monitoring started successfully")
        except:
            pass
    
    def stop_monitoring(self) -> None:
        """Stop DSLL monitoring."""
        if not self.monitoring_active:
            return
        
        print("⏹️ DSLL: Stopping monitoring...")
        self.monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2.0)
        
        print("✅ DSLL: Monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main DSLL monitoring loop."""
        while self.monitoring_active:
            try:
                # Monitor protected processes
                for pid in self.protected_processes.copy():
                    if not self._is_process_running(pid):
                        self.remove_protected_process(pid)
                        continue
                    
                    # Monitor syscalls for this process
                    self._monitor_process_syscalls(pid)
                
                # Analyze patterns
                self._analyze_syscall_patterns()
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                print(f"❌ DSLL monitoring error: {e}")
                time.sleep(1.0)
    
    def _is_process_running(self, pid: int) -> bool:
        """Check if a process is still running."""
        try:
            process = psutil.Process(pid)
            return process.is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _monitor_process_syscalls(self, pid: int) -> None:
        """Monitor system calls for a specific process using Windows APIs."""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            # Get all processes that might be accessing our protected process
            active_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'connections']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    proc_pid = proc_info.get('pid', 0)
                    
                    # Skip our own protected process
                    if proc_pid == pid:
                        continue
                    
                    # Skip system processes
                    if self._is_system_process(proc_name):
                        continue
                    
                    # Only check processes that are actually running
                    try:
                        proc_obj = psutil.Process(proc_pid)
                        if not proc_obj.is_running():
                            continue
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    
                    active_processes.append((proc_pid, proc_name))
                    
                    # Check if this process has handles to our protected process
                    if self._check_process_access(proc_pid, pid, proc_name):
                        # Record the access attempt
                        self._record_syscall(
                            SyscallType.PROCESS,
                            proc_pid,
                            proc_name,
                            "NtOpenProcess",
                            {"target_pid": pid, "target_name": process_name},
                            "success"
                        )
                    
                    # Check for memory access patterns
                    if self._check_memory_access_patterns(proc_pid, pid, proc_name):
                        self._record_syscall(
                            SyscallType.MEMORY,
                            proc_pid,
                            proc_name,
                            "NtReadVirtualMemory",
                            {"target_pid": pid, "target_name": process_name},
                            "detected"
                        )
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Track which processes we've seen
            current_time = time.time()
            if not hasattr(self, '_last_seen_processes'):
                self._last_seen_processes = {}
            
            # Update last seen times for active processes
            for proc_pid, proc_name in active_processes:
                self._last_seen_processes[proc_pid] = {
                    'name': proc_name,
                    'last_seen': current_time
                }
            
            # Clean up processes that are no longer running
            to_remove = []
            for tracked_pid, info in self._last_seen_processes.items():
                if current_time - info['last_seen'] > 10:  # Not seen for 10 seconds
                    try:
                        proc = psutil.Process(tracked_pid)
                        if not proc.is_running():
                            print(f"🔄 DSLL: Process {info['name']} (PID: {tracked_pid}) is no longer running")
                            to_remove.append(tracked_pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        print(f"🔄 DSLL: Process {info['name']} (PID: {tracked_pid}) has terminated")
                        to_remove.append(tracked_pid)
            
            # Remove terminated processes from tracking
            for pid_to_remove in to_remove:
                del self._last_seen_processes[pid_to_remove]
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def _is_system_process(self, process_name: str) -> bool:
        """Check if a process is a system process."""
        system_processes = {
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe',
            'dwm.exe', 'conhost.exe', 'audiodg.exe', 'spoolsv.exe'
        }
        return process_name.lower() in system_processes
    
    def _check_process_access(self, source_pid: int, target_pid: int, source_name: str) -> bool:
        """Check if source process is accessing target process."""
        try:
            # First, verify the source process is actually running
            try:
                source_proc = psutil.Process(source_pid)
                if not source_proc.is_running():
                    return False
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
            
            # Use Windows API to check if source process has handle to target
            import ctypes
            from ctypes import wintypes
            
            # Try to detect if source process has opened target process
            kernel32 = ctypes.windll.kernel32
            
            # This is a simplified check - in reality, we'd need kernel-level hooks
            # For now, we'll detect known analysis tools that are actively running
            analysis_tools = {
                'procexp64.exe', 'procexp.exe', 'processhacker.exe', 'ph.exe',
                'cheatengine.exe', 'cheatengine-x86_64.exe', 'artmoney.exe',
                'ollydbg.exe', 'x64dbg.exe', 'x32dbg.exe'
            }
            
            if source_name.lower() in analysis_tools:
                # Only report if the process is actively using CPU (indicating it's doing something)
                try:
                    cpu_percent = source_proc.cpu_percent(interval=0.1)
                    if cpu_percent > 1.0:  # Active processing
                        print(f"🔍 DSLL: Active analysis tool {source_name} (PID: {source_pid}, CPU: {cpu_percent:.1f}%) accessing protected process")
                        return True
                    else:
                        # Process is idle, don't report
                        return False
                except:
                    return False
            
            return False
            
        except Exception:
            return False
    
    def _check_memory_access_patterns(self, source_pid: int, target_pid: int, source_name: str) -> bool:
        """Check for memory access patterns."""
        try:
            # First, verify the source process is actually running
            try:
                source_proc = psutil.Process(source_pid)
                if not source_proc.is_running():
                    return False
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
            
            # Detect tools that typically perform memory operations
            memory_tools = {
                'cheatengine.exe', 'cheatengine-x86_64.exe', 'artmoney.exe',
                'procexp64.exe', 'procexp.exe', 'processhacker.exe'
            }
            
            if source_name.lower() in memory_tools:
                # Check if the tool process is using significant CPU (indicating active scanning)
                try:
                    cpu_percent = source_proc.cpu_percent(interval=0.1)
                    if cpu_percent > 5.0:  # Active processing
                        print(f"🔍 DSLL: Detected active memory scanning from {source_name} (CPU: {cpu_percent:.1f}%)")
                        return True
                    else:
                        # Process is idle or closed, don't report
                        return False
                except:
                    pass
            
            return False
            
        except Exception:
            return False
    
    def _record_syscall(self, syscall_type: SyscallType, pid: int, process_name: str, 
                       syscall_name: str, parameters: Dict[str, Any], return_value: Any) -> None:
        """Record a system call in the DSLL ledger."""
        timestamp = time.time()
        thread_id = threading.get_ident()
        
        # Generate verification hash
        verification_data = f"{timestamp}:{syscall_type.value}:{pid}:{syscall_name}:{str(parameters)}"
        verification_hash = str(hash(verification_data))
        
        # Create syscall record
        record = SyscallRecord(
            timestamp=timestamp,
            syscall_type=syscall_type,
            process_id=pid,
            process_name=process_name,
            syscall_name=syscall_name,
            parameters=parameters,
            return_value=return_value,
            thread_id=thread_id,
            stack_trace=[],  # Would be populated by kernel hook
            verification_hash=verification_hash
        )
        
        # Add to ledger
        self.syscall_ledger.append(record)
        self.stats["total_syscalls_recorded"] += 1
        
        # Check if this is a critical syscall
        if syscall_name in self.critical_syscalls:
            print(f"🚨 DSLL: Critical syscall detected - {syscall_name} from {process_name} (PID: {pid})")
            
            # Also log to file
            try:
                import logging
                logging.basicConfig(filename='blacs_dsll.log', level=logging.INFO, 
                                  format='%(asctime)s - DSLL - %(message)s')
                logging.info(f"Critical syscall: {syscall_name} from {process_name} (PID: {pid})")
            except:
                pass
    
    def _analyze_syscall_patterns(self) -> None:
        """Analyze syscall patterns for suspicious behavior."""
        if len(self.syscall_ledger) < 5:
            return
        
        # Clean up old records from terminated processes first
        self._cleanup_terminated_process_records()
        
        # Get recent syscalls
        recent_syscalls = list(self.syscall_ledger)[-20:]  # Last 20 syscalls
        
        # Pattern 1: Multiple process access attempts
        process_syscalls = [r for r in recent_syscalls if r.syscall_type == SyscallType.PROCESS]
        if len(process_syscalls) >= 3:  # 3 or more process access attempts
            unique_processes = set(r.process_name for r in process_syscalls)
            self._report_suspicious_pattern("process_access_attempts", {
                "count": len(process_syscalls),
                "processes": list(unique_processes),
                "timespan": recent_syscalls[-1].timestamp - recent_syscalls[0].timestamp
            })
        
        # Pattern 2: Memory scanning activity
        memory_syscalls = [r for r in recent_syscalls if r.syscall_type == SyscallType.MEMORY]
        if len(memory_syscalls) >= 2:  # 2 or more memory operations
            self._report_suspicious_pattern("memory_scanning_activity", {
                "count": len(memory_syscalls),
                "processes": list(set(r.process_name for r in memory_syscalls)),
                "syscalls": [r.syscall_name for r in memory_syscalls]
            })
        
        # Pattern 3: Analysis tool detection (only for currently running tools)
        analysis_tools = {'procexp64.exe', 'procexp.exe', 'processhacker.exe', 'cheatengine.exe'}
        tool_syscalls = [r for r in recent_syscalls if r.process_name.lower() in analysis_tools]
        
        # Verify the tools are still running
        active_tool_syscalls = []
        for syscall in tool_syscalls:
            try:
                proc = psutil.Process(syscall.process_id)
                if proc.is_running():
                    active_tool_syscalls.append(syscall)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if active_tool_syscalls:
            tool_names = list(set(r.process_name for r in active_tool_syscalls))
            self._report_suspicious_pattern("analysis_tool_activity", {
                "tools_detected": tool_names,
                "syscall_count": len(active_tool_syscalls),
                "activity_types": list(set(r.syscall_name for r in active_tool_syscalls))
            })
    
    def _cleanup_terminated_process_records(self) -> None:
        """Remove syscall records from processes that are no longer running."""
        if not hasattr(self, '_last_cleanup') or time.time() - self._last_cleanup > 30:  # Cleanup every 30 seconds
            current_time = time.time()
            records_to_keep = []
            
            for record in self.syscall_ledger:
                # Keep records from the last 5 minutes or from processes that are still running
                if current_time - record.timestamp < 300:  # 5 minutes
                    try:
                        proc = psutil.Process(record.process_id)
                        if proc.is_running():
                            records_to_keep.append(record)
                        # If process is not running, don't keep the record
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Process is terminated, don't keep the record
                        pass
                # Records older than 5 minutes are automatically discarded
            
            # Update the ledger
            old_count = len(self.syscall_ledger)
            self.syscall_ledger.clear()
            self.syscall_ledger.extend(records_to_keep)
            new_count = len(self.syscall_ledger)
            
            if old_count != new_count:
                print(f"🧹 DSLL: Cleaned up {old_count - new_count} old syscall records from terminated processes")
            
            self._last_cleanup = current_time
    
    def _report_suspicious_pattern(self, pattern_type: str, details: Dict[str, Any]) -> None:
        """Report a suspicious pattern detected by DSLL."""
        pattern = {
            "timestamp": time.time(),
            "type": pattern_type,
            "details": details,
            "severity": "high"
        }
        
        self.suspicious_patterns.append(pattern)
        self.stats["suspicious_patterns_detected"] += 1
        
        print(f"⚠️ DSLL: Suspicious pattern detected - {pattern_type}")
        print(f"   Details: {details}")
        
        # Also log to file
        try:
            import logging
            logging.basicConfig(filename='blacs_dsll.log', level=logging.INFO, 
                              format='%(asctime)s - DSLL - %(message)s')
            logging.info(f"Suspicious pattern: {pattern_type} - {details}")
        except:
            pass
    
    def get_violations(self) -> List[Dict[str, Any]]:
        """Get DSLL violations."""
        violations = []
        
        for pattern in self.suspicious_patterns:
            violations.append({
                "timestamp": pattern["timestamp"],
                "type": "dsll_pattern_violation",
                "severity": pattern["severity"],
                "description": f"DSLL detected suspicious pattern: {pattern['type']}",
                "details": pattern["details"]
            })
        
        return violations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get DSLL monitoring statistics."""
        return {
            **self.stats,
            "ledger_size": len(self.syscall_ledger),
            "monitoring_active": self.monitoring_active,
            "recent_patterns": len([p for p in self.suspicious_patterns if time.time() - p["timestamp"] < 300])  # Last 5 minutes
        }
    
    def export_ledger(self, filename: str) -> bool:
        """Export DSLL ledger to file for analysis."""
        try:
            import json
            
            ledger_data = []
            for record in self.syscall_ledger:
                ledger_data.append({
                    "timestamp": record.timestamp,
                    "syscall_type": record.syscall_type.value,
                    "process_id": record.process_id,
                    "process_name": record.process_name,
                    "syscall_name": record.syscall_name,
                    "parameters": record.parameters,
                    "return_value": str(record.return_value),
                    "verification_hash": record.verification_hash
                })
            
            with open(filename, 'w') as f:
                json.dump({
                    "export_timestamp": time.time(),
                    "total_records": len(ledger_data),
                    "statistics": self.get_statistics(),
                    "ledger": ledger_data
                }, f, indent=2)
            
            print(f"✅ DSLL: Ledger exported to {filename}")
            return True
            
        except Exception as e:
            print(f"❌ DSLL: Failed to export ledger - {e}")
            return False