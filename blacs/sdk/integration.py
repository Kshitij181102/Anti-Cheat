"""
BLACS Integration SDK - Simplified

Easy-to-use SDK for integrating BLACS anti-cheat protection into any application.
"""

import os
import sys
import time
import threading
from typing import Dict, Any, Optional, Callable

from ..blacs_system import BLACSSystem


class BLACSIntegration:
    """Simplified BLACS Integration SDK."""
    
    def __init__(self, app_name: str, app_version: str = "1.0.0"):
        """Initialize BLACS integration."""
        self.app_name = app_name
        self.app_version = app_version
        self.app_pid = os.getpid()
        
        self.is_protected = False
        self.protection_level = "medium"
        self.violation_callbacks: Dict[str, Callable] = {}
        
        self.blacs_system: Optional[BLACSSystem] = None
    
    def enable_protection(self, protection_level: str = "medium") -> bool:
        """Enable BLACS anti-cheat protection."""
        print(f"🛡️  Enabling BLACS protection for {self.app_name}...")
        
        self.protection_level = protection_level
        
        try:
            # Create BLACS system
            self.blacs_system = BLACSSystem.create_default_system()
            
            # Configure target process for memory monitor
            if self.blacs_system.memory_monitor:
                self.blacs_system.memory_monitor.set_target_process(self.app_name)
                self.blacs_system.memory_monitor.add_protected_process(self.app_pid)
            
            # Start monitoring
            self.blacs_system.start_monitoring()
            
            self.is_protected = True
            print(f"✅ BLACS protection enabled for {self.app_name}")
            print(f"🔒 Protection Level: {protection_level.upper()}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to enable BLACS protection: {e}")
            return False
    
    def disable_protection(self) -> bool:
        """Disable BLACS protection."""
        if not self.is_protected:
            return True
        
        print("⏹️  Disabling BLACS protection...")
        
        try:
            if self.blacs_system:
                self.blacs_system.stop_monitoring()
            
            self.is_protected = False
            print("✅ BLACS protection disabled.")
            return True
            
        except Exception as e:
            print(f"❌ Failed to disable BLACS protection: {e}")
            return False
    
    def set_violation_callback(self, severity: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Set callback function for handling violations."""
        self.violation_callbacks[severity] = callback
    
    def get_protection_status(self) -> Dict[str, Any]:
        """Get current protection status."""
        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "app_pid": self.app_pid,
            "is_protected": self.is_protected,
            "protection_level": self.protection_level,
            "system_status": self.blacs_system.get_system_status() if self.blacs_system else None
        }


# Decorator for easy protection
def blacs_protected(app_name: str, protection_level: str = "medium"):
    """Decorator to easily add BLACS protection to any function."""
    def decorator(func):
        blacs = BLACSIntegration(app_name)
        blacs.enable_protection(protection_level)
        
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        wrapper._blacs = blacs
        return wrapper
    
    return decorator


# Context manager for temporary protection
class BLACSProtection:
    """Context manager for temporary BLACS protection."""
    
    def __init__(self, app_name: str, protection_level: str = "medium"):
        self.blacs = BLACSIntegration(app_name)
        self.protection_level = protection_level
    
    def __enter__(self):
        self.blacs.enable_protection(self.protection_level)
        return self.blacs
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.blacs.disable_protection()