#!/usr/bin/env python3
"""
BLACS Configuration Manager

Centralized configuration management for BLACS Guardian system.
Handles loading, validation, and management of all system settings.
"""

import json
import os
from typing import Dict, Any, Optional, List

class BLACSConfig:
    """BLACS Configuration Manager."""
    
    def __init__(self, config_file: str = "blacs_config.json"):
        """Initialize configuration manager."""
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> bool:
        """Load configuration from JSON file."""
        try:
            if not os.path.exists(self.config_file):
                print(f"⚠️ Configuration file not found: {self.config_file}")
                print("   Creating default configuration...")
                self.create_default_config()
                return True
            
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            print(f"✅ Configuration loaded from {self.config_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load configuration: {e}")
            print("   Creating default configuration...")
            self.create_default_config()
            return False
    
    def save_config(self) -> bool:
        """Save current configuration to JSON file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to save configuration: {e}")
            return False
    
    def create_default_config(self) -> None:
        """Create default configuration."""
        self.config = {
            "system": {
                "name": "BLACS Guardian",
                "version": "1.0.0",
                "admin_required": True,
                "self_protection": True
            },
            "protection_levels": {
                "high": {
                    "max_human_frequency": 15.0,
                    "automation_threshold": 0.6,
                    "auto_terminate": True,
                    "extreme_detection": True,
                    "dsll_enabled": True,
                    "scan_interval": 2.0,
                    "critical_risk_threshold": 0.85
                }
            },
            "monitors": {
                "process_monitor": {"enabled": True},
                "memory_monitor": {"enabled": True},
                "dsll_monitor": {"enabled": True}
            }
        }
        self.save_config()
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'system.name')."""
        try:
            keys = key_path.split('.')
            value = self.config
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            
            return value
            
        except Exception:
            return default
    
    def set(self, key_path: str, value: Any) -> bool:
        """Set configuration value using dot notation."""
        try:
            keys = key_path.split('.')
            config_ref = self.config
            
            # Navigate to the parent of the target key
            for key in keys[:-1]:
                if key not in config_ref:
                    config_ref[key] = {}
                config_ref = config_ref[key]
            
            # Set the final value
            config_ref[keys[-1]] = value
            return True
            
        except Exception as e:
            print(f"❌ Failed to set configuration {key_path}: {e}")
            return False
    
    def get_protection_level_config(self, level: str) -> Dict[str, Any]:
        """Get configuration for a specific protection level."""
        return self.get(f"protection_levels.{level}", {})
    
    def get_monitor_config(self, monitor_name: str) -> Dict[str, Any]:
        """Get configuration for a specific monitor."""
        return self.get(f"monitors.{monitor_name}", {})
    
    def get_dsll_config(self) -> Dict[str, Any]:
        """Get DSLL configuration."""
        return self.get("dsll_configuration", {})
    
    def get_threat_signatures(self, category: str = None) -> List[str]:
        """Get threat signatures for a category or all categories."""
        if category:
            return self.get(f"threat_detection.signature_database.{category}", [])
        else:
            # Return all signatures combined
            all_signatures = []
            signature_db = self.get("threat_detection.signature_database", {})
            for signatures in signature_db.values():
                if isinstance(signatures, list):
                    all_signatures.extend(signatures)
            return all_signatures
    
    def is_monitor_enabled(self, monitor_name: str) -> bool:
        """Check if a monitor is enabled."""
        return self.get(f"monitors.{monitor_name}.enabled", False)
    
    def is_dsll_enabled(self) -> bool:
        """Check if DSLL is enabled."""
        return self.get("dsll_configuration.enabled", False)
    
    def get_critical_syscalls(self) -> List[str]:
        """Get list of critical syscalls for DSLL monitoring."""
        return self.get("dsll_configuration.critical_syscalls", [])
    
    def get_response_action(self, severity: str) -> Dict[str, Any]:
        """Get response action configuration for a severity level."""
        return self.get(f"response_actions.violation_handling.{severity}_severity", {})
    
    def add_custom_signature(self, signature: str) -> bool:
        """Add a custom threat signature."""
        try:
            custom_sigs = self.get("advanced_settings.custom_signatures.user_defined_patterns", [])
            if signature not in custom_sigs:
                custom_sigs.append(signature)
                self.set("advanced_settings.custom_signatures.user_defined_patterns", custom_sigs)
                return True
            return False
        except Exception:
            return False
    
    def add_whitelist_process(self, process_name: str) -> bool:
        """Add a process to the whitelist."""
        try:
            whitelist = self.get("advanced_settings.custom_signatures.whitelist_processes", [])
            if process_name not in whitelist:
                whitelist.append(process_name)
                self.set("advanced_settings.custom_signatures.whitelist_processes", whitelist)
                return True
            return False
        except Exception:
            return False
    
    def get_whitelist_processes(self) -> List[str]:
        """Get whitelisted processes."""
        return self.get("advanced_settings.custom_signatures.whitelist_processes", [])
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Check required sections
        required_sections = ["system", "protection_levels", "monitors"]
        for section in required_sections:
            if section not in self.config:
                issues.append(f"Missing required section: {section}")
        
        # Check protection levels
        protection_levels = self.get("protection_levels", {})
        if not protection_levels:
            issues.append("No protection levels defined")
        
        # Check monitors
        monitors = self.get("monitors", {})
        if not any(self.is_monitor_enabled(name) for name in monitors.keys()):
            issues.append("No monitors are enabled")
        
        return issues
    
    def print_config_summary(self) -> None:
        """Print a summary of the current configuration."""
        print("🔧 BLACS Configuration Summary")
        print("=" * 35)
        
        # System info
        system_name = self.get("system.name", "Unknown")
        system_version = self.get("system.version", "Unknown")
        print(f"System: {system_name} v{system_version}")
        
        # Protection levels
        levels = list(self.get("protection_levels", {}).keys())
        print(f"Protection Levels: {', '.join(levels)}")
        
        # Enabled monitors
        enabled_monitors = []
        for monitor in self.get("monitors", {}):
            if self.is_monitor_enabled(monitor):
                enabled_monitors.append(monitor)
        print(f"Enabled Monitors: {', '.join(enabled_monitors)}")
        
        # DSLL status
        dsll_status = "ENABLED" if self.is_dsll_enabled() else "DISABLED"
        print(f"DSLL Technology: {dsll_status}")
        
        # Threat signatures
        total_signatures = len(self.get_threat_signatures())
        print(f"Threat Signatures: {total_signatures}")
        
        # Custom settings
        custom_sigs = len(self.get("advanced_settings.custom_signatures.user_defined_patterns", []))
        whitelist_count = len(self.get_whitelist_processes())
        print(f"Custom Signatures: {custom_sigs}")
        print(f"Whitelisted Processes: {whitelist_count}")

# Global configuration instance
config = BLACSConfig()

def get_config() -> BLACSConfig:
    """Get the global configuration instance."""
    return config

def reload_config() -> bool:
    """Reload configuration from file."""
    return config.load_config()

def save_config() -> bool:
    """Save current configuration to file."""
    return config.save_config()