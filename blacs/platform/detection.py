"""
Platform detection utilities for BLACS.

This module provides utilities to detect the current operating system
and abstract platform-specific differences through unified interfaces.
"""

import platform
import sys
from enum import Enum
from typing import Dict, Any, Optional, List


class SupportedPlatform(Enum):
    """Enumeration of supported platforms."""
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class PlatformDetector:
    """Utility class for detecting and managing platform-specific behavior."""
    
    _instance: Optional['PlatformDetector'] = None
    _platform: Optional[SupportedPlatform] = None
    
    def __new__(cls) -> 'PlatformDetector':
        """Singleton pattern implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize the platform detector."""
        if self._platform is None:
            self._detect_platform()
    
    def _detect_platform(self) -> None:
        """Detect the current platform."""
        system = platform.system().lower()
        
        if system == "linux":
            self._platform = SupportedPlatform.LINUX
        elif system == "windows":
            self._platform = SupportedPlatform.WINDOWS
        else:
            self._platform = SupportedPlatform.UNKNOWN
    
    @property
    def current_platform(self) -> SupportedPlatform:
        """Get the current platform."""
        return self._platform
    
    @property
    def is_linux(self) -> bool:
        """Check if running on Linux."""
        return self._platform == SupportedPlatform.LINUX
    
    @property
    def is_windows(self) -> bool:
        """Check if running on Windows."""
        return self._platform == SupportedPlatform.WINDOWS
    
    @property
    def is_supported(self) -> bool:
        """Check if the current platform is supported."""
        return self._platform in [SupportedPlatform.LINUX, SupportedPlatform.WINDOWS]
    
    def get_platform_info(self) -> Dict[str, Any]:
        """Get detailed platform information."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": sys.version,
            "detected_platform": self._platform.value if self._platform else "unknown",
            "is_supported": self.is_supported
        }
    
    def get_platform_specific_config(self) -> Dict[str, Any]:
        """Get platform-specific configuration parameters."""
        if self.is_linux:
            return {
                "proc_path": "/proc",
                "use_ptrace": True,
                "use_strace": True,
                "syscall_interface": "linux",
                "process_enumeration": "proc_filesystem"
            }
        elif self.is_windows:
            return {
                "use_winapi": True,
                "use_toolhelp32": True,
                "syscall_interface": "windows",
                "process_enumeration": "winapi"
            }
        else:
            return {
                "syscall_interface": "unsupported",
                "process_enumeration": "unsupported"
            }
    
    def validate_platform_requirements(self) -> tuple[bool, List[str]]:
        """Validate that platform requirements are met."""
        errors = []
        
        if not self.is_supported:
            errors.append(f"Unsupported platform: {platform.system()}")
            return False, errors
        
        # Check Python version
        if sys.version_info < (3, 8):
            errors.append("Python 3.8 or higher is required")
        
        # Platform-specific checks
        if self.is_linux:
            try:
                import os
                if not os.path.exists("/proc"):
                    errors.append("/proc filesystem not available")
            except Exception as e:
                errors.append(f"Linux platform validation failed: {e}")
        
        elif self.is_windows:
            try:
                import ctypes
                # Test basic Windows API access
                ctypes.windll.kernel32.GetCurrentProcessId()
            except Exception as e:
                errors.append(f"Windows API access failed: {e}")
        
        return len(errors) == 0, errors


# Global platform detector instance
platform_detector = PlatformDetector()