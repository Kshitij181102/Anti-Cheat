#!/usr/bin/env python3
"""
BLACS Configuration with Advanced DSLL Technology

Configuration system for BLACS anti-cheat with DSLL support.
"""

# =================================================================
# PROTECTION LEVELS
# =================================================================

PROTECTION_LEVELS = {
    "low": {
        "max_human_frequency": 50.0,
        "automation_threshold": 0.8,
        "auto_terminate": False,
        "extreme_detection": False,
        "dsll_enabled": False
    },
    "medium": {
        "max_human_frequency": 25.0,
        "automation_threshold": 0.7,
        "auto_terminate": True,
        "extreme_detection": True,
        "dsll_enabled": True
    },
    "high": {
        "max_human_frequency": 15.0,
        "automation_threshold": 0.6,
        "auto_terminate": True,
        "extreme_detection": True,
        "dsll_enabled": True
    },
    "maximum": {
        "max_human_frequency": 10.0,
        "automation_threshold": 0.5,
        "auto_terminate": True,
        "extreme_detection": True,
        "dsll_enabled": True
    }
}

# =================================================================
# CURRENT SETTINGS (EDIT THESE)
# =================================================================

# Choose protection level: "low", "medium", "high", "maximum"
PROTECTION_LEVEL = "high"

# Monitor enable/disable
ENABLE_INPUT_MONITOR = True
ENABLE_PROCESS_MONITOR = True
ENABLE_MEMORY_MONITOR = True
ENABLE_DSLL_MONITOR = True  # Advanced DSLL Technology

# Get current level settings
CURRENT_SETTINGS = PROTECTION_LEVELS[PROTECTION_LEVEL]

# Apply settings
MAX_HUMAN_FREQUENCY = CURRENT_SETTINGS["max_human_frequency"]
AUTOMATION_THRESHOLD = CURRENT_SETTINGS["automation_threshold"]
AUTO_TERMINATE_THREATS = CURRENT_SETTINGS["auto_terminate"]
EXTREME_DETECTION_MODE = CURRENT_SETTINGS["extreme_detection"]
DSLL_ENABLED = CURRENT_SETTINGS["dsll_enabled"]

# Additional thresholds
SCAN_INTERVAL = 2.0  # seconds
CRITICAL_RISK_THRESHOLD = 0.9
MEMORY_CHECK_INTERVAL = 1.0

# =================================================================
# DSLL (Deterministic Syscall Lockstep Ledger) CONFIGURATION
# =================================================================

DSLL_CONFIG = {
    "enabled": DSLL_ENABLED,
    "monitor_interval": 0.1,  # 100ms for high-frequency monitoring
    "ledger_max_size": 10000,  # Maximum syscall records to keep
    "critical_syscalls": [
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
    ],
    "pattern_detection": {
        "rapid_memory_threshold": 10,  # Syscalls in recent history
        "process_manipulation_threshold": 5,
        "analysis_window": 50  # Number of recent syscalls to analyze
    },
    "export_settings": {
        "auto_export": False,  # Automatically export ledger on violations
        "export_format": "json",
        "include_stack_traces": True,
        "compress_exports": False
    }
}