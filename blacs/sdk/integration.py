"""
BLACS Integration SDK - Hybrid Architecture

Easy-to-use SDK for integrating BLACS anti-cheat protection with hybrid 
user-level + kernel-level capabilities into any application.
"""

import os
import sys
import time
import threading
from typing import Dict, Any, Optional, Callable, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ..blacs_system import BLACSSystem
from blacs_hybrid_config import ProtectionMode, set_protection_mode, get_recommended_protection_mode


class BLACSIntegration:
    """Hybrid BLACS Integration SDK with kernel-level support."""
    
    def __init__(self, app_name: str, app_version: str = "1.0.0", protection_mode: str = "auto"):
        """Initialize BLACS integration with hybrid architecture support."""
        self.app_name = app_name
        self.app_version = app_version
        self.app_pid = os.getpid()
        
        self.is_protected = False
        self.violation_callbacks: Dict[str, Callable] = {}
        
        # Determine protection mode
        if protection_mode == "auto":
            self.protection_mode = get_recommended_protection_mode()
        else:
            # Map string to enum
            mode_mapping = {
                "user_basic": ProtectionMode.USER_BASIC,
                "user_advanced": ProtectionMode.USER_ADVANCED,
                "hybrid_standard": ProtectionMode.HYBRID_STANDARD,
                "hybrid_maximum": ProtectionMode.HYBRID_MAXIMUM,
                "kernel_enterprise": ProtectionMode.KERNEL_ENTERPRISE
            }
            self.protection_mode = mode_mapping.get(protection_mode, ProtectionMode.USER_ADVANCED)
        
        self.blacs_system: Optional[BLACSSystem] = None
    
    def enable_protection(self, protection_mode: Optional[str] = None) -> bool:
        """Enable BLACS anti-cheat protection with hybrid architecture."""
        print(f"🛡️  Enabling BLACS hybrid protection for {self.app_name}...")
        
        # Update protection mode if specified
        if protection_mode:
            mode_mapping = {
                "user_basic": ProtectionMode.USER_BASIC,
                "user_advanced": ProtectionMode.USER_ADVANCED,
                "hybrid_standard": ProtectionMode.HYBRID_STANDARD,
                "hybrid_maximum": ProtectionMode.HYBRID_MAXIMUM,
                "kernel_enterprise": ProtectionMode.KERNEL_ENTERPRISE
            }
            self.protection_mode = mode_mapping.get(protection_mode, self.protection_mode)
        
        try:
            # Set global protection mode
            set_protection_mode(self.protection_mode)
            
            # Create BLACS system with hybrid architecture
            self.blacs_system = BLACSSystem.create_default_system(self.protection_mode)
            
            # Configure target process for memory monitor
            if self.blacs_system.memory_monitor:
                self.blacs_system.memory_monitor.set_target_process(self.app_name)
                self.blacs_system.memory_monitor.add_protected_process(self.app_pid)
            
            # Start monitoring
            self.blacs_system.start_monitoring()
            
            self.is_protected = True
            
            # Print protection summary
            config = self.blacs_system.config
            print(f"✅ BLACS protection enabled for {self.app_name}")
            print(f"🔒 Protection Mode: {self.protection_mode.value.upper()}")
            print(f"📊 Detection Strength: {config.get('detection_strength', 'unknown').upper()}")
            print(f"⚡ Performance Impact: {config.get('performance_impact', 'unknown').upper()}")
            
            if self.blacs_system.kernel_features_enabled:
                print("🔴 Kernel-level protection: ACTIVE")
            else:
                print("🔵 User-level protection: ACTIVE")
            
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
        """Get current protection status with hybrid architecture details."""
        status = {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "app_pid": self.app_pid,
            "is_protected": self.is_protected,
            "protection_mode": self.protection_mode.value,
            "system_status": self.blacs_system.get_system_status() if self.blacs_system else None
        }
        
        if self.blacs_system:
            system_status = self.blacs_system.get_system_status()
            status.update({
                "kernel_features_enabled": system_status.get("kernel_features_enabled", False),
                "detection_strength": system_status.get("configuration", {}).get("detection_strength", "unknown"),
                "performance_impact": system_status.get("configuration", {}).get("performance_impact", "unknown")
            })
        
        return status
    
    def switch_protection_mode(self, new_mode: str) -> bool:
        """Switch to a different protection mode."""
        if not self.is_protected:
            print("❌ Protection not enabled")
            return False
        
        mode_mapping = {
            "user_basic": ProtectionMode.USER_BASIC,
            "user_advanced": ProtectionMode.USER_ADVANCED,
            "hybrid_standard": ProtectionMode.HYBRID_STANDARD,
            "hybrid_maximum": ProtectionMode.HYBRID_MAXIMUM,
            "kernel_enterprise": ProtectionMode.KERNEL_ENTERPRISE
        }
        
        new_protection_mode = mode_mapping.get(new_mode)
        if not new_protection_mode:
            print(f"❌ Invalid protection mode: {new_mode}")
            return False
        
        if self.blacs_system.switch_protection_mode(new_protection_mode):
            self.protection_mode = new_protection_mode
            print(f"✅ Switched to protection mode: {new_mode}")
            return True
        else:
            print(f"❌ Failed to switch to protection mode: {new_mode}")
            return False
    
    def get_available_protection_modes(self) -> List[str]:
        """Get list of available protection modes."""
        return [
            "user_basic",
            "user_advanced", 
            "hybrid_standard",
            "hybrid_maximum",
            "kernel_enterprise"
        ]


# Decorator for easy protection with hybrid architecture
def blacs_protected(app_name: str, protection_mode: str = "auto"):
    """Decorator to easily add BLACS hybrid protection to any function."""
    def decorator(func):
        blacs = BLACSIntegration(app_name, protection_mode=protection_mode)
        blacs.enable_protection()
        
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        wrapper._blacs = blacs
        return wrapper
    
    return decorator


# Context manager for temporary protection with hybrid architecture
class BLACSProtection:
    """Context manager for temporary BLACS hybrid protection."""
    
    def __init__(self, app_name: str, protection_mode: str = "auto"):
        self.blacs = BLACSIntegration(app_name, protection_mode=protection_mode)
        self.protection_mode = protection_mode
    
    def __enter__(self):
        self.blacs.enable_protection()
        return self.blacs
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.blacs.disable_protection()