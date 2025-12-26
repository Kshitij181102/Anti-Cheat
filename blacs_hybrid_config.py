#!/usr/bin/env python3
"""
BLACS Hybrid Configuration

Configuration system for hybrid user-level + kernel-level protection.
"""

import os
import platform
from enum import Enum
from typing import Dict, Any, Optional

class ProtectionMode(Enum):
    """Protection mode enumeration."""
    USER_BASIC = "user_basic"
    USER_ADVANCED = "user_advanced"
    HYBRID_STANDARD = "hybrid_standard"
    HYBRID_MAXIMUM = "hybrid_maximum"
    KERNEL_ENTERPRISE = "kernel_enterprise"

class KernelModuleStatus(Enum):
    """Kernel module status."""
    NOT_AVAILABLE = "not_available"
    AVAILABLE = "available"
    LOADED = "loaded"
    ERROR = "error"

# =================================================================
# HYBRID PROTECTION LEVELS
# =================================================================

PROTECTION_CONFIGS = {
    ProtectionMode.USER_BASIC: {
        "description": "Basic user-level protection - lightweight and compatible",
        "kernel_module_required": False,
        "kernel_features_enabled": False,
        "user_level_features": {
            "process_monitoring": True,
            "memory_monitoring": True,
            "input_monitoring": True,
            "signature_detection": True,
            "behavioral_analysis": False,
            "advanced_memory_scanning": False
        },
        "performance_impact": "minimal",
        "detection_strength": "basic",
        "recommended_for": ["development", "testing", "lightweight_apps"]
    },
    
    ProtectionMode.USER_ADVANCED: {
        "description": "Advanced user-level protection - enhanced detection without kernel",
        "kernel_module_required": False,
        "kernel_features_enabled": False,
        "user_level_features": {
            "process_monitoring": True,
            "memory_monitoring": True,
            "input_monitoring": True,
            "signature_detection": True,
            "behavioral_analysis": True,
            "advanced_memory_scanning": True,
            "api_hooking_detection": True,
            "process_hollowing_detection": True
        },
        "performance_impact": "low",
        "detection_strength": "good",
        "recommended_for": ["games", "business_apps", "general_use"]
    },
    
    ProtectionMode.HYBRID_STANDARD: {
        "description": "Hybrid protection - user-level enhanced by kernel module",
        "kernel_module_required": True,
        "kernel_features_enabled": True,
        "user_level_features": {
            "process_monitoring": True,
            "memory_monitoring": True,
            "input_monitoring": True,
            "signature_detection": True,
            "behavioral_analysis": True,
            "advanced_memory_scanning": True,
            "api_hooking_detection": True,
            "process_hollowing_detection": True
        },
        "kernel_level_features": {
            "system_call_monitoring": True,
            "kernel_memory_protection": True,
            "process_creation_monitoring": True,
            "driver_load_monitoring": True,
            "registry_protection": True,
            "file_system_protection": False
        },
        "performance_impact": "medium",
        "detection_strength": "high",
        "recommended_for": ["competitive_games", "critical_apps", "enterprise"]
    },
    
    ProtectionMode.HYBRID_MAXIMUM: {
        "description": "Maximum hybrid protection - full user + kernel capabilities",
        "kernel_module_required": True,
        "kernel_features_enabled": True,
        "user_level_features": {
            "process_monitoring": True,
            "memory_monitoring": True,
            "input_monitoring": True,
            "signature_detection": True,
            "behavioral_analysis": True,
            "advanced_memory_scanning": True,
            "api_hooking_detection": True,
            "process_hollowing_detection": True,
            "hardware_fingerprinting": True,
            "network_monitoring": True
        },
        "kernel_level_features": {
            "system_call_monitoring": True,
            "kernel_memory_protection": True,
            "process_creation_monitoring": True,
            "driver_load_monitoring": True,
            "registry_protection": True,
            "file_system_protection": True,
            "hardware_event_monitoring": True,
            "interrupt_monitoring": True
        },
        "performance_impact": "medium-high",
        "detection_strength": "maximum",
        "recommended_for": ["high_security", "military", "financial"]
    },
    
    ProtectionMode.KERNEL_ENTERPRISE: {
        "description": "Full kernel-level protection - enterprise grade security",
        "kernel_module_required": True,
        "kernel_features_enabled": True,
        "user_level_features": {
            "process_monitoring": True,
            "memory_monitoring": True,
            "input_monitoring": True,
            "signature_detection": True,
            "behavioral_analysis": True,
            "advanced_memory_scanning": True,
            "api_hooking_detection": True,
            "process_hollowing_detection": True,
            "hardware_fingerprinting": True,
            "network_monitoring": True,
            "cloud_intelligence": True
        },
        "kernel_level_features": {
            "system_call_monitoring": True,
            "kernel_memory_protection": True,
            "process_creation_monitoring": True,
            "driver_load_monitoring": True,
            "registry_protection": True,
            "file_system_protection": True,
            "hardware_event_monitoring": True,
            "interrupt_monitoring": True,
            "rootkit_detection": True,
            "hypervisor_detection": True
        },
        "performance_impact": "high",
        "detection_strength": "enterprise",
        "recommended_for": ["enterprise", "government", "critical_infrastructure"]
    }
}

# =================================================================
# CURRENT CONFIGURATION
# =================================================================

# Default protection mode
CURRENT_PROTECTION_MODE = ProtectionMode.USER_ADVANCED

# Kernel module settings
KERNEL_MODULE_CONFIG = {
    "auto_load": True,
    "fallback_to_user_level": True,
    "require_admin_rights": True,
    "driver_path": "drivers/blacs_kernel.sys",
    "driver_service_name": "BLACSKernel",
    "signed_driver_required": True
}

# Advanced detection settings
ADVANCED_DETECTION_CONFIG = {
    "ai_behavioral_analysis": True,
    "cloud_threat_intelligence": False,
    "hardware_based_attestation": True,
    "real_time_signature_updates": True,
    "custom_signature_learning": False
}

# Performance tuning
PERFORMANCE_CONFIG = {
    "max_cpu_usage_percent": 2.0,
    "max_memory_usage_mb": 50,
    "scan_interval_user_level": 2.0,
    "scan_interval_kernel_level": 0.5,
    "thread_pool_size": 4,
    "priority_class": "normal"  # normal, high, realtime
}

# =================================================================
# HELPER FUNCTIONS
# =================================================================

def get_current_config() -> Dict[str, Any]:
    """Get current protection configuration."""
    return PROTECTION_CONFIGS[CURRENT_PROTECTION_MODE]

def is_kernel_module_required() -> bool:
    """Check if kernel module is required for current protection mode."""
    return get_current_config()["kernel_module_required"]

def get_recommended_protection_mode() -> ProtectionMode:
    """Get recommended protection mode based on system capabilities."""
    if platform.system() != "Windows":
        return ProtectionMode.USER_ADVANCED
    
    # Check if running as administrator
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False
    
    if is_admin and kernel_module_available():
        return ProtectionMode.HYBRID_STANDARD
    else:
        return ProtectionMode.USER_ADVANCED

def kernel_module_available() -> bool:
    """Check if kernel module is available."""
    driver_path = KERNEL_MODULE_CONFIG["driver_path"]
    return os.path.exists(driver_path)

def get_protection_mode_info(mode: ProtectionMode) -> Dict[str, Any]:
    """Get detailed information about a protection mode."""
    return PROTECTION_CONFIGS[mode]

def set_protection_mode(mode: ProtectionMode) -> bool:
    """Set the protection mode."""
    global CURRENT_PROTECTION_MODE
    
    config = PROTECTION_CONFIGS[mode]
    
    # Check if kernel module is required but not available
    if config["kernel_module_required"] and not kernel_module_available():
        print(f"⚠️  Kernel module required for {mode.value} but not available")
        return False
    
    CURRENT_PROTECTION_MODE = mode
    print(f"✅ Protection mode set to: {mode.value}")
    return True

def print_current_config():
    """Print current configuration summary."""
    config = get_current_config()
    
    print(f"\n🛡️  BLACS Hybrid Configuration")
    print(f"=" * 40)
    print(f"Protection Mode: {CURRENT_PROTECTION_MODE.value.upper()}")
    print(f"Description: {config['description']}")
    print(f"Kernel Module Required: {config['kernel_module_required']}")
    print(f"Detection Strength: {config['detection_strength'].upper()}")
    print(f"Performance Impact: {config['performance_impact'].upper()}")
    
    print(f"\n📊 User-Level Features:")
    for feature, enabled in config["user_level_features"].items():
        status = "✅" if enabled else "❌"
        print(f"   {status} {feature.replace('_', ' ').title()}")
    
    if "kernel_level_features" in config:
        print(f"\n🔴 Kernel-Level Features:")
        for feature, enabled in config["kernel_level_features"].items():
            status = "✅" if enabled else "❌"
            print(f"   {status} {feature.replace('_', ' ').title()}")
    
    print(f"\n💡 Recommended For: {', '.join(config['recommended_for'])}")

# =================================================================
# CONFIGURATION VALIDATION
# =================================================================

def validate_configuration() -> tuple[bool, list[str]]:
    """Validate current configuration."""
    errors = []
    
    # Check if kernel module is required but not available
    if is_kernel_module_required() and not kernel_module_available():
        errors.append("Kernel module required but not found")
    
    # Check admin rights for kernel features
    if is_kernel_module_required():
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                errors.append("Administrator rights required for kernel features")
        except:
            errors.append("Cannot determine administrator status")
    
    # Check platform compatibility
    if platform.system() not in ["Windows", "Linux"]:
        errors.append(f"Platform {platform.system()} not fully supported")
    
    return len(errors) == 0, errors

if __name__ == "__main__":
    print_current_config()
    
    # Validate configuration
    is_valid, errors = validate_configuration()
    if not is_valid:
        print(f"\n❌ Configuration Errors:")
        for error in errors:
            print(f"   • {error}")
    else:
        print(f"\n✅ Configuration is valid")