"""
Memory Monitor component for BLACS.

This module implements memory monitoring functionality to detect unauthorized
memory modifications, tampering, and external tool access patterns.
"""

import hashlib
import time
import threading
import psutil
import os
from typing import List, Dict, Any, Optional, Set

from ..core.interfaces import MemoryMonitorInterface
from ..core.data_models import (
    MemoryRegion, MemoryAccess, Violation, ViolationSeverity
)
from ..platform.detection import platform_detector


class MemoryMonitor(MemoryMonitorInterface):
    """Memory monitoring component that detects unauthorized modifications and external tool access."""
    
    def __init__(self, hash_algorithm: str = "sha256"):
        """
        Initialize the memory monitor.
        
        Args:
            hash_algorithm: Hashing algorithm to use for integrity checks
        """
        super().__init__("MemoryMonitor")
        self.hash_algorithm = hash_algorithm
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Protected memory regions and their baseline hashes
        self.protected_regions: List[MemoryRegion] = []
        self.baseline_hashes: Dict[str, str] = {}
        self.access_log: List[MemoryAccess] = []
        
        # Monitoring parameters
        self.check_interval = 1.0  # seconds between integrity checks
        self.max_access_frequency = 100  # max accesses per second per region
        
        # External tool detection (ENHANCED - more precise)
        self.cheat_tools = {
            # Specific cheat engine variants
            "cheatengine", "cheat engine", "cheat-engine",
            
            # Memory editors (exact matches)
            "artmoney", "gameguardian", "memoryeditor", "memoryhacker", 
            "memhack", "tsearch", "scanmem",
            
            # Debuggers (when used for cheating)
            "ollydbg", "x64dbg", "x32dbg", 
            
            # Injection tools (specific)
            "dllinjector", "processinjector", "codecave",
            "hooklib", "easyhook", "detours", "minhook",
            
            # Known trainers
            "trainer", "gametrainer", "fling", "mrantifun"
        }
        
        # Track protected processes
        self.protected_processes: Set[int] = set()
        self.target_process_name: Optional[str] = None
    
    def start_monitoring(self) -> None:
        """Start the memory monitoring process."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.stop_event.clear()
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop the memory monitoring process."""
        if self.monitoring_thread:
            self.stop_event.set()
            self.monitoring_thread.join(timeout=2.0)
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop for memory integrity checks."""
        while not self.stop_event.is_set():
            try:
                # Check memory integrity if we have protected regions
                if self.protected_regions and self.baseline_hashes:
                    violations = self.detect_memory_modifications(self.baseline_hashes)
                    self.violations.extend(violations)
                
                # Monitor memory access patterns
                access_patterns = self.monitor_memory_access_patterns()
                self.access_log.extend(access_patterns)
                
                # Analyze access patterns for suspicious behavior
                self._analyze_access_patterns()
                
                # ENHANCED: Detect external memory manipulation tools
                external_violations = self._detect_external_memory_tools()
                self.violations.extend(external_violations)
                
                # ENHANCED: Check for process memory access by external tools
                if self.protected_processes:
                    access_violations = self._detect_external_process_access()
                    self.violations.extend(access_violations)
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                # Log error and continue monitoring
                violation = Violation(
                    component=self.name,
                    severity=ViolationSeverity.LOW,
                    description=f"Memory monitoring error: {str(e)}",
                    evidence={"error_type": type(e).__name__}
                )
                self.violations.append(violation)
                time.sleep(self.check_interval)
    
    def hash_memory_regions(self, regions: List[MemoryRegion]) -> Dict[str, str]:
        """
        Generate hashes for memory regions.
        
        Args:
            regions: List of memory regions to hash
            
        Returns:
            Dictionary mapping region identifiers to their hashes
        """
        region_hashes = {}
        
        for region in regions:
            try:
                # Create a unique identifier for the region
                region_id = f"{region.start_address:x}_{region.size}_{region.name or 'unnamed'}"
                
                # In a real implementation, this would read actual memory content
                # For now, we'll simulate by hashing region metadata
                content = f"{region.start_address}_{region.size}_{region.permissions}_{time.time()}"
                
                # Generate cryptographic hash
                hasher = hashlib.new(self.hash_algorithm)
                hasher.update(content.encode('utf-8'))
                region_hash = hasher.hexdigest()
                
                region_hashes[region_id] = region_hash
                
            except Exception as e:
                # Log hashing error but continue with other regions
                violation = Violation(
                    component=self.name,
                    severity=ViolationSeverity.LOW,
                    description=f"Memory hashing error for region {region.start_address:x}: {str(e)}",
                    evidence={
                        "region_start": region.start_address,
                        "region_size": region.size,
                        "error_type": type(e).__name__
                    }
                )
                self.violations.append(violation)
        
        return region_hashes
    
    def detect_memory_modifications(self, baseline: Dict[str, str]) -> List[Violation]:
        """
        Detect unauthorized memory modifications.
        
        Args:
            baseline: Baseline hashes to compare against
            
        Returns:
            List of detected violations
        """
        violations = []
        
        # Re-hash current memory regions
        current_hashes = self.hash_memory_regions(self.protected_regions)
        
        # Compare with baseline
        for region_id, baseline_hash in baseline.items():
            current_hash = current_hashes.get(region_id)
            
            if current_hash is None:
                # Region no longer exists or accessible
                violations.append(Violation(
                    component=self.name,
                    severity=ViolationSeverity.HIGH,
                    description=f"Protected memory region disappeared: {region_id}",
                    evidence={
                        "region_id": region_id,
                        "baseline_hash": baseline_hash
                    }
                ))
            elif current_hash != baseline_hash:
                # Hash mismatch indicates modification
                violations.append(Violation(
                    component=self.name,
                    severity=ViolationSeverity.CRITICAL,
                    description=f"Unauthorized memory modification detected: {region_id}",
                    evidence={
                        "region_id": region_id,
                        "baseline_hash": baseline_hash,
                        "current_hash": current_hash,
                        "modification_time": time.time()
                    }
                ))
        
        # Check for new regions that weren't in baseline
        for region_id, current_hash in current_hashes.items():
            if region_id not in baseline:
                violations.append(Violation(
                    component=self.name,
                    severity=ViolationSeverity.MEDIUM,
                    description=f"New memory region detected: {region_id}",
                    evidence={
                        "region_id": region_id,
                        "current_hash": current_hash,
                        "detection_time": time.time()
                    }
                ))
        
        return violations
    
    def monitor_memory_access_patterns(self) -> List[MemoryAccess]:
        """
        Monitor memory access patterns.
        
        Returns:
            List of recent memory access events
        """
        # In a real implementation, this would use platform-specific APIs
        # to monitor actual memory accesses. For now, we'll simulate.
        
        access_events = []
        current_time = time.time()
        
        # Simulate some memory access events for testing
        for region in self.protected_regions:
            # Simulate normal access pattern
            access = MemoryAccess(
                timestamp=current_time,
                address=region.start_address + 0x100,
                access_type="read",
                size=4,
                process_id=1234  # Current process
            )
            access_events.append(access)
        
        return access_events
    
    def _analyze_access_patterns(self) -> None:
        """Analyze memory access patterns for suspicious behavior."""
        if len(self.access_log) < 10:
            return  # Need sufficient data for analysis
        
        current_time = time.time()
        recent_accesses = [
            access for access in self.access_log 
            if current_time - access.timestamp <= 1.0  # Last second
        ]
        
        # Check for excessive access frequency
        if len(recent_accesses) > self.max_access_frequency:
            violation = Violation(
                component=self.name,
                severity=ViolationSeverity.HIGH,
                description=f"Excessive memory access frequency: {len(recent_accesses)} accesses/sec",
                evidence={
                    "access_count": len(recent_accesses),
                    "threshold": self.max_access_frequency,
                    "time_window": 1.0
                }
            )
            self.violations.append(violation)
        
        # Check for suspicious access patterns (e.g., external processes)
        external_accesses = [
            access for access in recent_accesses 
            if access.process_id != 1234  # Not our process
        ]
        
        if external_accesses:
            violation = Violation(
                component=self.name,
                severity=ViolationSeverity.CRITICAL,
                description=f"External process memory access detected: {len(external_accesses)} accesses",
                evidence={
                    "external_access_count": len(external_accesses),
                    "external_pids": list(set(access.process_id for access in external_accesses)),
                    "access_types": list(set(access.access_type for access in external_accesses))
                }
            )
            self.violations.append(violation)
        
        # Trim old access log entries to prevent memory bloat
        cutoff_time = current_time - 60.0  # Keep last minute
        self.access_log = [
            access for access in self.access_log 
            if access.timestamp > cutoff_time
        ]
    
    def _detect_external_memory_tools(self) -> List[Violation]:
        """Detect external memory manipulation tools like Cheat Engine."""
        violations = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '') or ''
                    proc_exe = proc_info.get('exe', '') or ''
                    proc_cmdline = ' '.join(proc_info.get('cmdline', []) or [])
                    
                    # Convert to lowercase for comparison
                    proc_name = proc_name.lower()
                    proc_exe = proc_exe.lower()
                    proc_cmdline = proc_cmdline.lower()
                    
                    # Check against cheat tool database (exact matches only)
                    for cheat_tool in self.cheat_tools:
                        if (cheat_tool == proc_name or  # Exact name match
                            cheat_tool in proc_exe or   # In executable path
                            (len(cheat_tool) > 4 and cheat_tool in proc_cmdline)):  # In command line (longer names only)
                            
                            violations.append(Violation(
                                component=self.name,
                                severity=ViolationSeverity.CRITICAL,
                                description=f"External memory manipulation tool detected: {proc_info.get('name', 'Unknown')}",
                                evidence={
                                    "tool_type": cheat_tool,
                                    "process_name": proc_info.get('name'),
                                    "process_id": proc_info.get('pid'),
                                    "executable_path": proc_info.get('exe'),
                                    "command_line": proc_cmdline,
                                    "detection_time": time.time()
                                }
                            ))
                            
                            # Try to terminate the cheat process
                            try:
                                proc.terminate()
                                print(f"🚫 BLACS: Terminated cheat tool: {proc_info.get('name')}")
                            except:
                                print(f"⚠️  BLACS: Could not terminate cheat tool: {proc_info.get('name')} (admin privileges required)")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            violations.append(Violation(
                component=self.name,
                severity=ViolationSeverity.LOW,
                description=f"External tool detection error: {str(e)}",
                evidence={"error_type": type(e).__name__}
            ))
        
        return violations
    
    def _detect_external_process_access(self) -> List[Violation]:
        """Detect external processes accessing protected process memory."""
        violations = []
        
        if not self.target_process_name:
            return violations
        
        try:
            # Find target processes
            target_processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                if self.target_process_name.lower() in proc.info['name'].lower():
                    target_processes.append(proc)
                    self.protected_processes.add(proc.pid)
            
            # Check for external processes that might be accessing target memory
            for target_proc in target_processes:
                for proc in psutil.process_iter(['pid', 'name', 'connections']):
                    try:
                        if proc.pid == target_proc.pid:
                            continue
                        
                        proc_name = proc.info.get('name', '').lower()
                        
                        # Check if this process is a known memory manipulation tool
                        is_cheat_tool = any(tool in proc_name for tool in self.cheat_tools)
                        
                        # Check for suspicious process names that might access memory
                        suspicious_patterns = ['debug', 'hack', 'inject', 'hook', 'trace', 'monitor']
                        is_suspicious = any(pattern in proc_name for pattern in suspicious_patterns)
                        
                        if is_cheat_tool or is_suspicious:
                            violations.append(Violation(
                                component=self.name,
                                severity=ViolationSeverity.CRITICAL,
                                description=f"Suspicious process detected near protected process: {proc.info.get('name')} -> {self.target_process_name}",
                                evidence={
                                    "suspicious_process": proc.info.get('name'),
                                    "suspicious_pid": proc.pid,
                                    "target_process": self.target_process_name,
                                    "target_pid": target_proc.pid,
                                    "is_known_cheat_tool": is_cheat_tool,
                                    "detection_time": time.time()
                                }
                            ))
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            violations.append(Violation(
                component=self.name,
                severity=ViolationSeverity.LOW,
                description=f"External process access detection error: {str(e)}",
                evidence={"error_type": type(e).__name__}
            ))
        
        return violations
    
    def set_target_process(self, process_name: str) -> None:
        """Set the target process to monitor for external access."""
        self.target_process_name = process_name
        print(f"🛡️  BLACS Memory Monitor: Now protecting process '{process_name}'")
    
    def add_protected_process(self, pid: int) -> None:
        """Add a process ID to the protected processes set."""
        self.protected_processes.add(pid)
    
    def add_protected_region(self, region: MemoryRegion) -> None:
        """
        Add a memory region to protection.
        
        Args:
            region: MemoryRegion to protect
        """
        self.protected_regions.append(region)
        
        # Generate baseline hash for the new region
        region_hashes = self.hash_memory_regions([region])
        self.baseline_hashes.update(region_hashes)
    
    def remove_protected_region(self, start_address: int) -> None:
        """
        Remove a memory region from protection.
        
        Args:
            start_address: Start address of region to remove
        """
        # Remove from protected regions
        self.protected_regions = [
            region for region in self.protected_regions 
            if region.start_address != start_address
        ]
        
        # Remove from baseline hashes
        region_ids_to_remove = [
            region_id for region_id in self.baseline_hashes.keys()
            if region_id.startswith(f"{start_address:x}_")
        ]
        for region_id in region_ids_to_remove:
            del self.baseline_hashes[region_id]
    
    def get_violations(self) -> List[Violation]:
        """Get all detected violations."""
        return self.violations.copy()
    
    def get_memory_integrity_report(self) -> Dict[str, Any]:
        """
        Get a comprehensive memory integrity report.
        
        Returns:
            Dictionary containing integrity status and statistics
        """
        current_hashes = self.hash_memory_regions(self.protected_regions)
        
        integrity_status = {}
        for region_id, baseline_hash in self.baseline_hashes.items():
            current_hash = current_hashes.get(region_id)
            integrity_status[region_id] = {
                "baseline_hash": baseline_hash,
                "current_hash": current_hash,
                "integrity_intact": current_hash == baseline_hash if current_hash else False
            }
        
        return {
            "protected_regions_count": len(self.protected_regions),
            "baseline_hashes_count": len(self.baseline_hashes),
            "integrity_status": integrity_status,
            "recent_access_count": len([
                access for access in self.access_log 
                if time.time() - access.timestamp <= 60.0
            ]),
            "violations_count": len(self.violations),
            "last_check_time": time.time()
        }