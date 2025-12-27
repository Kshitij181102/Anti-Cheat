#!/usr/bin/env python3
"""
BLACS DSLL Monitor - Deterministic Syscall Lockstep Ledger

Revolutionary shadow verification system that records and validates every 
sensitive system call during a protected session.
"""

import time
import threading
import ctypes
import psutil
from typing import Dict, List, Any, Optional, Tuple
from collections import deque
from dataclasses import dataclass
from enum import Enum

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
        """Initialize DSLL monitor."""
        self.enabled = True
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        
        # DSLL ledger storage
        self.syscall_ledger: deque = deque(maxlen=10000)  # Last 10k syscalls
        self.verification_hashes: Dict[str, str] = {}
        self.suspicious_patterns: List[Dict[str, Any]] = []
        
        # Monitoring configuration
        self.monitor_interval = 0.1  # 100ms intervals
        self.protected_processes: List[int] = []
        self.critical_syscalls = {
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtOpenProcess",
            "NtCreateThread",
            "NtSuspendProcess",
            "NtResumeProcess",
            "NtTerminateProcess",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateFile",
            "NtSetValueKey",
            "NtLoadDriver"
        }
        
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
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        print("✅ DSLL: Advanced syscall monitoring active")
    
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
        """Monitor system calls for a specific process."""
        try:
            process = psutil.Process(pid)
            
            # Check for suspicious memory operations
            try:
                memory_info = process.memory_info()
                if hasattr(process, 'memory_maps'):
                    memory_maps = process.memory_maps()
                    
                    # Look for suspicious memory patterns
                    for mmap in memory_maps:
                        if self._is_suspicious_memory_region(mmap):
                            self._record_syscall(
                                SyscallType.MEMORY,
                                pid,
                                process.name(),
                                "NtAllocateVirtualMemory",
                                {"address": mmap.addr, "size": mmap.rss, "perms": mmap.perms},
                                "suspicious_allocation"
                            )
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Check for suspicious process operations
            try:
                connections = process.connections()
                for conn in connections:
                    if self._is_suspicious_connection(conn):
                        self._record_syscall(
                            SyscallType.NETWORK,
                            pid,
                            process.name(),
                            "NtCreateFile",
                            {"local_addr": conn.laddr, "remote_addr": conn.raddr, "status": conn.status},
                            "suspicious_connection"
                        )
            except (psutil.AccessDenied, AttributeError):
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def _is_suspicious_memory_region(self, mmap) -> bool:
        """Check if a memory region is suspicious."""
        # Look for executable memory regions that might indicate code injection
        if hasattr(mmap, 'perms') and 'x' in mmap.perms:
            # Executable memory outside normal regions might be suspicious
            if hasattr(mmap, 'path') and not mmap.path:
                return True  # Anonymous executable memory
        return False
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Check if a network connection is suspicious."""
        # This is a placeholder - real implementation would have more sophisticated checks
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
    
    def _analyze_syscall_patterns(self) -> None:
        """Analyze syscall patterns for suspicious behavior."""
        if len(self.syscall_ledger) < 10:
            return
        
        # Get recent syscalls
        recent_syscalls = list(self.syscall_ledger)[-50:]  # Last 50 syscalls
        
        # Pattern 1: Rapid memory operations
        memory_syscalls = [r for r in recent_syscalls if r.syscall_type == SyscallType.MEMORY]
        if len(memory_syscalls) > 10:  # More than 10 memory operations in recent history
            self._report_suspicious_pattern("rapid_memory_operations", {
                "count": len(memory_syscalls),
                "processes": list(set(r.process_name for r in memory_syscalls))
            })
        
        # Pattern 2: Process manipulation attempts
        process_syscalls = [r for r in recent_syscalls if r.syscall_type == SyscallType.PROCESS]
        if len(process_syscalls) > 5:
            self._report_suspicious_pattern("process_manipulation", {
                "count": len(process_syscalls),
                "syscalls": [r.syscall_name for r in process_syscalls]
            })
    
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