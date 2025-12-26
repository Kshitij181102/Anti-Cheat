"""
Main BLACS system orchestrator - Hybrid Architecture.

This module contains the main BLACSSystem class that coordinates
essential monitoring components with optional kernel-level protection.
"""

from typing import List, Optional, Dict, Any
import time
import threading
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .core.interfaces import (
    InputMonitorInterface, MemoryMonitorInterface, ProcessMonitorInterface
)
from .core.data_models import MonitoringData, Violation
from .monitors.process_monitor_windows import WindowsProcessMonitor
from .kernel.kernel_monitor import KernelMonitor
from blacs_hybrid_config import ProtectionMode, get_current_config, is_kernel_module_required


class BLACSSystem:
    """Hybrid BLACS system orchestrator with kernel-level support."""
    
    def __init__(self, protection_mode: ProtectionMode = ProtectionMode.USER_ADVANCED):
        """Initialize the BLACS system with specified protection mode."""
        self.protection_mode = protection_mode
        self.config = get_current_config()
        
        # User-level monitors
        self.input_monitor: Optional[InputMonitorInterface] = None
        self.memory_monitor: Optional[MemoryMonitorInterface] = None
        self.process_monitor: Optional[ProcessMonitorInterface] = None
        
        # Kernel-level monitor
        self.kernel_monitor: Optional[KernelMonitor] = None
        self.kernel_features_enabled = False
        
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.monitoring_interval = 1.0  # seconds
        
        # Initialize kernel monitor if required
        if is_kernel_module_required():
            self._initialize_kernel_monitor()
    
    def _initialize_kernel_monitor(self) -> bool:
        """Initialize kernel-level monitoring."""
        try:
            print("🔧 Initializing kernel-level monitoring...")
            self.kernel_monitor = KernelMonitor()
            
            if self.kernel_monitor.initialize():
                self.kernel_features_enabled = True
                print("✅ Kernel monitoring initialized successfully")
                return True
            else:
                print("⚠️ Kernel monitoring initialization failed, falling back to user-level only")
                self.kernel_monitor = None
                return False
                
        except Exception as e:
            print(f"❌ Kernel monitor initialization error: {e}")
            self.kernel_monitor = None
            return False
    
    @classmethod
    def create_default_system(cls, protection_mode: ProtectionMode = ProtectionMode.USER_ADVANCED) -> 'BLACSSystem':
        """Create a BLACS system with default monitors and specified protection mode."""
        from .monitors.input_monitor import InputMonitor
        from .monitors.memory_monitor import MemoryMonitor
        
        blacs = cls(protection_mode)
        
        # Register essential monitors based on configuration
        config = blacs.config
        user_features = config.get("user_level_features", {})
        
        if user_features.get("input_monitoring", True):
            blacs.register_input_monitor(InputMonitor())
        
        if user_features.get("memory_monitoring", True):
            blacs.register_memory_monitor(MemoryMonitor())
        
        if user_features.get("process_monitoring", True):
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
        """Start the monitoring process with hybrid architecture support."""
        if self.monitoring_active:
            return
        
        print(f"🚀 Starting BLACS monitoring in {self.protection_mode.value.upper()} mode...")
        
        # Start user-level monitors
        monitors = [self.input_monitor, self.memory_monitor, self.process_monitor]
        
        for monitor in monitors:
            if monitor and monitor.enabled:
                monitor.start_monitoring()
        
        # Start kernel-level monitoring if available
        if self.kernel_monitor and self.kernel_features_enabled:
            kernel_features = list(self.config.get("kernel_level_features", {}).keys())
            enabled_features = [f for f in kernel_features if self.config["kernel_level_features"][f]]
            
            if enabled_features:
                print(f"🔴 Starting kernel monitoring with features: {', '.join(enabled_features)}")
                self.kernel_monitor.start_monitoring(enabled_features)
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        print("✅ BLACS monitoring started successfully")
    
    def stop_monitoring(self) -> None:
        """Stop the monitoring process."""
        if not self.monitoring_active:
            return
        
        print("⏹️ Stopping BLACS monitoring...")
        
        self.monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        
        # Stop kernel-level monitoring first
        if self.kernel_monitor:
            self.kernel_monitor.stop_monitoring()
        
        # Stop user-level monitors
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
        """Get the current system status including hybrid architecture info."""
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
        
        # Add kernel monitoring status
        kernel_status = {}
        if self.kernel_monitor:
            kernel_status = self.kernel_monitor.get_monitoring_statistics()
        
        return {
            "protection_mode": self.protection_mode.value,
            "monitoring_active": self.monitoring_active,
            "kernel_features_enabled": self.kernel_features_enabled,
            "user_level_monitors": monitors_status,
            "kernel_level_monitor": kernel_status,
            "configuration": {
                "description": self.config.get("description", ""),
                "detection_strength": self.config.get("detection_strength", "unknown"),
                "performance_impact": self.config.get("performance_impact", "unknown")
            }
        }
    
    def switch_protection_mode(self, new_mode: ProtectionMode) -> bool:
        """Switch to a different protection mode."""
        if self.monitoring_active:
            print("⚠️ Cannot switch protection mode while monitoring is active")
            return False
        
        print(f"🔄 Switching protection mode from {self.protection_mode.value} to {new_mode.value}")
        
        # Update protection mode and configuration
        self.protection_mode = new_mode
        self.config = get_current_config()
        
        # Reinitialize kernel monitor if needed
        if is_kernel_module_required() and not self.kernel_monitor:
            self._initialize_kernel_monitor()
        elif not is_kernel_module_required() and self.kernel_monitor:
            self.kernel_monitor.shutdown()
            self.kernel_monitor = None
            self.kernel_features_enabled = False
        
        print(f"✅ Protection mode switched to {new_mode.value}")
        return True
    
    def get_available_protection_modes(self) -> List[str]:
        """Get list of available protection modes."""
        return [mode.value for mode in ProtectionMode]
    
    def shutdown(self) -> bool:
        """Shutdown the BLACS system completely."""
        print("🔧 Shutting down BLACS system...")
        
        # Stop monitoring
        self.stop_monitoring()
        
        # Shutdown kernel monitor
        if self.kernel_monitor:
            self.kernel_monitor.shutdown()
        
        print("✅ BLACS system shutdown complete")
        return True