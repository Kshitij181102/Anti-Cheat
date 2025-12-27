#!/usr/bin/env python3
"""
BLACS Simple Configuration

Simplified configuration system for BLACS anti-cheat.
"""

# =================================================================
# PROTECTION LEVELS
# =================================================================

PROTECTION_LEVELS = {
    "low": {
        "max_human_frequency": 50.0,
        "automation_threshold": 0.8,
        "auto_terminate": False,
        "extreme_detection": False
    },
    "medium": {
        "max_human_frequency": 25.0,
        "automation_threshold": 0.7,
        "auto_terminate": True,
        "extreme_detection": True
    },
    "high": {
        "max_human_frequency": 15.0,
        "automation_threshold": 0.6,
        "auto_terminate": True,
        "extreme_detection": True
    },
    "maximum": {
        "max_human_frequency": 10.0,
        "automation_threshold": 0.5,
        "auto_terminate": True,
        "extreme_detection": True
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

# Get current level settings
CURRENT_SETTINGS = PROTECTION_LEVELS[PROTECTION_LEVEL]

# Apply settings
MAX_HUMAN_FREQUENCY = CURRENT_SETTINGS["max_human_frequency"]
AUTOMATION_THRESHOLD = CURRENT_SETTINGS["automation_threshold"]
AUTO_TERMINATE_THREATS = CURRENT_SETTINGS["auto_terminate"]
EXTREME_DETECTION_MODE = CURRENT_SETTINGS["extreme_detection"]

# Additional thresholds
SCAN_INTERVAL = 2.0  # seconds
CRITICAL_RISK_THRESHOLD = 0.9
MEMORY_CHECK_INTERVAL = 1.0