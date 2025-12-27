"""
Main BLACS system orchestrator - Simplified version.

This module contains the main BLACSSystem class that coordinates
essential monitoring components.
"""

from typing import List, Optional, Dict, Any
import time
import threading
from .core.interfaces import (
    InputMonitorInterface, MemoryMonitorInterface, ProcessMonitorInterface
)
from .core.data_models import MonitoringData, Violation
from .monitors.process_monitor_windows import WindowsProcessMonitor


class BLACSSystem:
    """Simplified BLACS system orchestrator."""
    
    def __init__(self):
        """Initialize the BLACS system."""
        self.input_monitor: Optional[InputMonitorInterface] = None
        self.memory_monitor: Optional[MemoryMonitorInterface] = None
        self.process_monitor: Optional[ProcessMonitorInterface] = None
        
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.monitoring_interval = 1.0  # seconds
    
    @classmethod
    def create_default_system(cls) -> 'BLACSSystem':
        """Create a BLACS system with default monitors."""
        from .monitors.input_monitor import InputMonitor
        from .monitors.memory_monitor import MemoryMonitor
        
        blacs = cls()
        
        # Register essential monitors
        blacs.register_input_monitor(InputMonitor())
        blacs.register_memory_monitor(MemoryMonitor())
        blacs.register_process_monitor(WindowsProcessMonitor())
        
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
    
    def start_monitoring(self) -> None:
        """Start the monitoring process."""
        if self.monitoring_active:
            return
        
        # Start all monitors
        monitors = [self.input_monitor, self.memory_monitor, self.process_monitor]
        
        for monitor in monitors:
            if monitor and monitor.enabled:
                monitor.start_monitoring()
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop the monitoring process."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        
        # Stop all monitors
        monitors = [self.input_monitor, self.memory_monitor, self.process_monitor]
        
        for monitor in monitors:
            if monitor:
                monitor.stop_monitoring()
    
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
        """Get the current system status."""
        monitors_status = {}
        
        monitors = {
            "input_monitor": self.input_monitor,
            "memory_monitor": self.memory_monitor,
            "process_monitor": self.process_monitor
        }
        
        for name, monitor in monitors.items():
            if monitor:
                monitors_status[name] = {
                    "enabled": monitor.enabled,
                    "violations_count": len(monitor.get_violations())
                }
            else:
                monitors_status[name] = {"enabled": False, "violations_count": 0}
        
        return {
            "monitoring_active": self.monitoring_active,
            "monitors": monitors_status
        }