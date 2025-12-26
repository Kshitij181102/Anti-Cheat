# BLACS Hybrid Architecture Guide

## Overview

BLACS (Behavioral Learning Anti-Cheat System) now features a revolutionary **hybrid architecture** that combines user-level and kernel-level protection for maximum security and flexibility.

## Architecture Components

### 🔵 User-Level Protection
- **Process Monitoring**: Detects suspicious processes and cheat tools
- **Memory Monitoring**: Scans for memory modifications and injections
- **Input Monitoring**: Analyzes input patterns for automation detection
- **Signature Detection**: Identifies known cheat tools and techniques
- **Behavioral Analysis**: Learns normal vs. suspicious behavior patterns

### 🔴 Kernel-Level Protection
- **System Call Monitoring**: Intercepts and analyzes system calls
- **Kernel Memory Protection**: Protects critical kernel structures
- **Process Creation Monitoring**: Monitors all process creation events
- **Driver Load Monitoring**: Detects suspicious driver installations
- **Registry Protection**: Prevents unauthorized registry modifications
- **Hardware Event Monitoring**: Monitors hardware-level events

## Protection Modes

### 1. User Basic (`user_basic`)
- **Description**: Lightweight user-level protection
- **Features**: Basic process, memory, and input monitoring
- **Performance Impact**: Minimal
- **Use Cases**: Development, testing, lightweight applications

### 2. User Advanced (`user_advanced`)
- **Description**: Enhanced user-level protection
- **Features**: All user-level features + behavioral analysis
- **Performance Impact**: Low
- **Use Cases**: Games, business applications, general use

### 3. Hybrid Standard (`hybrid_standard`)
- **Description**: User-level enhanced by kernel module
- **Features**: All user features + basic kernel monitoring
- **Performance Impact**: Medium
- **Use Cases**: Competitive games, critical applications

### 4. Hybrid Maximum (`hybrid_maximum`)
- **Description**: Full user + kernel capabilities
- **Features**: All features enabled
- **Performance Impact**: Medium-High
- **Use Cases**: High security, military, financial applications

### 5. Kernel Enterprise (`kernel_enterprise`)
- **Description**: Enterprise-grade kernel protection
- **Features**: Full feature set + cloud intelligence
- **Performance Impact**: High
- **Use Cases**: Enterprise, government, critical infrastructure

## Quick Start

### Basic Integration

```python
from blacs.sdk.integration import BLACSIntegration

# Create integration with automatic mode selection
blacs = BLACSIntegration("MyApp", "1.0.0", "auto")

# Enable protection
if blacs.enable_protection():
    print("✅ Protection enabled")
    
    # Your application code here
    run_my_application()
    
    # Disable protection
    blacs.disable_protection()
```

### Using Specific Protection Mode

```python
# Enable hybrid protection
blacs = BLACSIntegration("MyApp", "1.0.0", "hybrid_standard")
blacs.enable_protection()
```

### Using Decorator

```python
from blacs.sdk.integration import blacs_protected

@blacs_protected("MyApp", "hybrid_standard")
def my_protected_function():
    # This function is automatically protected
    pass
```

### Using Context Manager

```python
from blacs.sdk.integration import BLACSProtection

with BLACSProtection("MyApp", "hybrid_standard") as blacs:
    # Protection is automatically enabled
    run_my_application()
    # Protection is automatically disabled
```

## Configuration

### Automatic Mode Selection

BLACS automatically selects the best protection mode based on:
- **Administrator Privileges**: Required for kernel features
- **Kernel Module Availability**: Checks if kernel driver is available
- **System Compatibility**: Ensures compatibility with current OS
- **Performance Requirements**: Balances security vs. performance

### Manual Mode Selection

```python
# Available modes
modes = [
    "user_basic",
    "user_advanced", 
    "hybrid_standard",
    "hybrid_maximum",
    "kernel_enterprise"
]

# Set specific mode
blacs = BLACSIntegration("MyApp", protection_mode="hybrid_standard")
```

### Configuration File

Edit `blacs_hybrid_config.py` to customize:

```python
# Set default protection mode
CURRENT_PROTECTION_MODE = ProtectionMode.HYBRID_STANDARD

# Kernel module settings
KERNEL_MODULE_CONFIG = {
    "auto_load": True,
    "fallback_to_user_level": True,
    "require_admin_rights": True
}

# Performance tuning
PERFORMANCE_CONFIG = {
    "max_cpu_usage_percent": 2.0,
    "max_memory_usage_mb": 50,
    "scan_interval_user_level": 2.0,
    "scan_interval_kernel_level": 0.5
}
```

## Kernel Module Installation

### Windows

1. **Administrator Rights**: Run as Administrator
2. **Test Signing** (for unsigned drivers):
   ```cmd
   bcdedit /set testsigning on
   ```
3. **Install Driver**:
   ```python
   from blacs.kernel.driver_manager import DriverManager
   
   driver_manager = DriverManager()
   driver_manager.install_driver()
   ```

### Linux

1. **Root Privileges**: Run as root
2. **Install Module**:
   ```bash
   sudo insmod /lib/modules/blacs_kernel.ko
   ```

### Automatic Installation

BLACS can automatically handle kernel module installation:

```python
from blacs.kernel.kernel_interface import KernelInterface

kernel = KernelInterface()
if kernel.install_kernel_module():
    print("✅ Kernel module installed")
```

## Monitoring and Status

### Get Protection Status

```python
status = blacs.get_protection_status()
print(f"Mode: {status['protection_mode']}")
print(f"Kernel Features: {status['kernel_features_enabled']}")
print(f"Detection Strength: {status['detection_strength']}")
```

### Monitor System Status

```python
system_status = blacs.blacs_system.get_system_status()

# User-level monitors
user_monitors = system_status['user_level_monitors']
for monitor, info in user_monitors.items():
    print(f"{monitor}: {'✅' if info['enabled'] else '❌'}")

# Kernel-level monitor
kernel_monitor = system_status['kernel_level_monitor']
if kernel_monitor:
    print(f"Kernel Active: {kernel_monitor['monitoring_active']}")
    print(f"Features: {kernel_monitor['enabled_features']}")
```

## Security Features

### Tamper Resistance
- **Kernel-level protection** cannot be easily disabled by user processes
- **Driver protection** prevents unauthorized driver modifications
- **Memory protection** guards against memory patching
- **Process protection** prevents process termination

### Advanced Detection
- **Signature-based detection** for known cheat tools
- **Behavioral analysis** for unknown threats
- **Heuristic analysis** for suspicious patterns
- **Machine learning** for adaptive protection

### Real-time Response
- **Automatic threat termination**
- **Real-time alerts and logging**
- **Violation callbacks** for custom responses
- **Graduated response system**

## Performance Optimization

### CPU Usage
- **Configurable scan intervals**
- **Thread pool optimization**
- **Priority-based scheduling**
- **Adaptive monitoring intensity**

### Memory Usage
- **Efficient data structures**
- **Memory pool management**
- **Garbage collection optimization**
- **Configurable memory limits**

### I/O Optimization
- **Asynchronous operations**
- **Batch processing**
- **Intelligent caching**
- **Minimal disk access**

## Troubleshooting

### Common Issues

#### Kernel Module Not Loading
```
❌ Kernel module required but not found
```
**Solution**: Install kernel module or use user-level mode

#### Permission Denied
```
❌ Administrator privileges required
```
**Solution**: Run as Administrator/root or use user-level mode

#### Driver Signing Issues (Windows)
```
⚠️ Driver is not digitally signed
```
**Solution**: Enable test signing mode or use signed driver

### Fallback Behavior

BLACS automatically falls back to user-level protection when:
- Kernel module is not available
- Administrator privileges are missing
- Kernel module fails to load
- System compatibility issues

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable verbose output
blacs = BLACSIntegration("MyApp", "1.0.0", "hybrid_standard")
```

## Best Practices

### Development
- Start with `user_advanced` mode during development
- Use `hybrid_standard` for testing
- Deploy with `hybrid_maximum` for production

### Performance
- Monitor CPU and memory usage
- Adjust scan intervals based on requirements
- Use appropriate protection mode for use case

### Security
- Always use kernel-level protection in production
- Implement violation callbacks for custom responses
- Regularly update threat signatures
- Monitor system logs for suspicious activity

### Integration
- Initialize protection early in application startup
- Handle protection failures gracefully
- Provide user feedback on protection status
- Test with various protection modes

## API Reference

### BLACSIntegration Class

```python
class BLACSIntegration:
    def __init__(self, app_name: str, app_version: str = "1.0.0", 
                 protection_mode: str = "auto")
    
    def enable_protection(self, protection_mode: Optional[str] = None) -> bool
    def disable_protection(self) -> bool
    def get_protection_status(self) -> Dict[str, Any]
    def switch_protection_mode(self, new_mode: str) -> bool
    def get_available_protection_modes(self) -> List[str]
    def set_violation_callback(self, severity: str, callback: Callable)
```

### Protection Modes

- `"user_basic"` - Basic user-level protection
- `"user_advanced"` - Advanced user-level protection  
- `"hybrid_standard"` - Standard hybrid protection
- `"hybrid_maximum"` - Maximum hybrid protection
- `"kernel_enterprise"` - Enterprise kernel protection
- `"auto"` - Automatic mode selection

### Decorators and Context Managers

```python
@blacs_protected(app_name: str, protection_mode: str = "auto")
def protected_function():
    pass

with BLACSProtection(app_name: str, protection_mode: str = "auto") as blacs:
    # Protected code block
    pass
```

## Examples

See `hybrid_example.py` for comprehensive examples demonstrating:
- Different protection modes
- Automatic capability detection
- Decorator and context manager usage
- Status monitoring
- Error handling

## Support

For technical support and advanced configuration:
- Check system requirements
- Verify administrator privileges
- Review kernel module installation
- Monitor system logs
- Contact support team

---

**BLACS Hybrid Architecture** - Maximum security through intelligent layered protection.