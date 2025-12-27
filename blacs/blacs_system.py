"""
Main BLACS system orchestrator with Advanced DSLL Technology.

This module contains the main BLACSSystem class that coordinates
essential monitoring components including the revolutionary DSLL monitor.
"""

from typing import List, Optional, Dict, Any
import time
import threading
from .core.interfaces import (
    InputMonitorInterface, MemoryMonitorInterface, ProcessMonitorInterface
)
from .core.data_models import MonitoringData, Violation
from .monitors.process_monitor_windows import WindowsProcessMonitor
from .monitors.dsll_monitor import DSLLMonitor


class BLACSSystem:
    """Advanced BLACS system orchestrator with DSLL technology."""
    
    def __init__(self):
        """Initialize the BLACS system with DSLL support."""
        self.input_monitor: Optional[InputMonitorInterface] = None
        self.memory_monitor: Optional[MemoryMonitorInterface] = None
        self.process_monitor: Optional[ProcessMonitorInterface] = None
        self.dsll_monitor: Optional[DSLLMonitor] = None
        
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.monitoring_interval = 1.0  # seconds
    
    @classmethod
    def create_default_system(cls) -> 'BLACSSystem':
        """Create a BLACS system with default monitors including DSLL."""
        from .monitors.input_monitor import InputMonitor
        from .monitors.memory_monitor import MemoryMonitor
        
        blacs = cls()
        
        # Register essential monitors
        blacs.register_input_monitor(InputMonitor())
        blacs.register_memory_monitor(MemoryMonitor())
        blacs.register_process_monitor(WindowsProcessMonitor())
        
        # Register advanced DSLL monitor
        blacs.register_dsll_monitor(DSLLMonitor())
        
        return blacs
    
    def register_input_monitor(self, monitor: InputMonitorInterface) -> None:
        """Register an input monitor."""
        self.input_monitor = monitor
    
    def register_memory_monitor(self, monitor: MemoryMonitorInterface) -> None:
        """Register a memory monitor."""
        self.memory_monitor = monitor
    
    def register_process_monitor(self, monitor: ProcessMonitorInterface) -> None:
        """Register a process monitor."""
        self.process_monitor = monitor
    
    def register_dsll_monitor(self, monitor: DSLLMonitor) -> None:
        """Register the advanced DSLL monitor."""
        self.dsll_monitor = monitor
    
    def start_monitoring(self) -> None:
        """Start the monitoring process with DSLL support."""
        if self.monitoring_active:
            return
        
        print("🚀 Starting BLACS monitoring with Advanced DSLL Technology...")
        
        # Start all monitors
        monitors = [self.input_monitor, self.memory_monitor, self.process_monitor]
        
        for monitor in monitors:
            if monitor and monitor.enabled:
                monitor.start_monitoring()
        
        # Start advanced DSLL monitor
        if self.dsll_monitor and self.dsll_monitor.enabled:
            self.dsll_monitor.start_monitoring()
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        print("✅ BLACS monitoring started with DSLL protection")
    
    def stop_monitoring(self) -> None:
        """Stop the monitoring process."""
        if not self.monitoring_active:
            return
        
        print("⏹️ Stopping BLACS monitoring...")
        
        self.monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        
        # Stop DSLL monitor first
        if self.dsll_monitor:
            self.dsll_monitor.stop_monitoring()
        
        # Stop all other monitors
        monitors = [self.input_monitor, self.memory_monitor, self.process_monitor]
        
        for monitor in monitors:
            if monitor:
                monitor.stop_monitoring()
        
        print("✅ BLACS monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Simple monitoring - just let monitors run
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(self.monitoring_interval)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get the current system status including DSLL information."""
        monitors_status = {}
        
        monitors = {
            "input_monitor": self.input_monitor,
            "memory_monitor": self.memory_monitor,
            "process_monitor": self.process_monitor,
            "dsll_monitor": self.dsll_monitor
        }
        
        for name, monitor in monitors.items():
            if monitor:
                if name == "dsll_monitor":
                    # Special handling for DSLL monitor
                    dsll_stats = monitor.get_statistics()
                    monitors_status[name] = {
                        "enabled": monitor.enabled,
                        "violations_count": len(monitor.get_violations()),
                        "syscalls_recorded": dsll_stats.get("total_syscalls_recorded", 0),
                        "patterns_detected": dsll_stats.get("suspicious_patterns_detected", 0),
                        "protected_processes": dsll_stats.get("protected_processes", 0)
                    }
                else:
                    monitors_status[name] = {
                        "enabled": monitor.enabled,
                        "violations_count": len(monitor.get_violations())
                    }
            else:
                monitors_status[name] = {"enabled": False, "violations_count": 0}
        
        return {
            "monitoring_active": self.monitoring_active,
            "monitors": monitors_status,
            "dsll_technology": "active" if self.dsll_monitor and self.dsll_monitor.enabled else "inactive"
        }
    
    def add_protected_process(self, pid: int) -> None:
        """Add a process to DSLL protection."""
        if self.dsll_monitor:
            self.dsll_monitor.add_protected_process(pid)
    
    def export_dsll_ledger(self, filename: str) -> bool:
        """Export DSLL ledger for forensic analysis."""
        if self.dsll_monitor:
            return self.dsll_monitor.export_ledger(filename)
        return False