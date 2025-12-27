# 🛡️ BLACS - Simplified Anti-Cheat System

**BLACS** (Behavioral Learning Anti-Cheat System) is a lightweight, production-ready anti-cheat system that protects any software application from cheating attempts. It uses advanced behavioral analysis and real-time monitoring to detect and prevent cheat tools.

## ✨ Key Features

- **🔍 Comprehensive Detection**: Detects Cheat Engine, debuggers, injection tools, and automation
- **🛡️ Real-time Protection**: Continuous monitoring with immediate threat response
- **🌐 Universal Compatibility**: Works with any software - games, applications, utilities
- **⚡ Lightweight**: Minimal impact on application performance
- **🎯 Simple Configuration**: Easy-to-edit configuration file
- **🔧 Easy Integration**: Simple SDK for quick integration

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install psutil
```

### 2. Run the Example
```bash
python example.py
```

### 3. Test with Real Applications
```bash
# Try opening Cheat Engine while the example is running
# BLACS will detect and alert immediately!
```

## 🎯 What BLACS Detects

### Cheat Tools (500+ Signatures)
- **Memory Editors**: Cheat Engine, ArtMoney, GameGuardian, Memory Hacker
- **Debuggers**: OllyDbg, x64dbg, IDA Pro, WinDbg, Process Hacker
- **Injection Tools**: DLL Injectors, Process Injectors, Code Cave tools
- **Speed Hacks**: Game Speed modifiers, Time manipulation tools
- **Trainers**: Fling Trainers, MrAntiFun, WeMod, Plitch
- **Automation**: Auto-clickers, Bots, Macro tools, AutoHotkey
- **General**: Any process with cheat/hack/mod/crack/bot in name

### Suspicious Behavior
- **Process Analysis**: Suspicious names, paths, and executables
- **Memory Protection**: External memory access detection
- **Real-time Scanning**: Continuous threat monitoring
- **Automatic Termination**: Immediate cheat tool elimination

## 🔧 Configuration

### Simple Configuration File
Edit `config.py` to adjust all settings:

```python
# Choose protection level: "low", "medium", "high", "maximum"
PROTECTION_LEVEL = "high"

# Monitor enable/disable
ENABLE_INPUT_MONITOR = True
ENABLE_PROCESS_MONITOR = True
ENABLE_MEMORY_MONITOR = True

# Additional settings
AUTO_TERMINATE_THREATS = True
EXTREME_DETECTION_MODE = True
```

### Protection Levels
- **Low**: Relaxed detection, fewer false positives
- **Medium**: Balanced detection (recommended)
- **High**: Strict detection, catches more cheats
- **Maximum**: Extreme sensitivity

## 💻 Integration Examples

### Simple Protection
```python
from blacs.sdk.integration import BLACSIntegration

# Initialize protection
blacs = BLACSIntegration("MyApp")
blacs.enable_protection(protection_level="high")

# Your application code here
run_my_application()

# Disable when done
blacs.disable_protection()
```

### With Violation Callbacks
```python
def on_cheat_detected(violation_data):
    print(f"CHEAT DETECTED: {violation_data['description']}")
    # Take action - close app, ban user, etc.

blacs.set_violation_callback("critical", on_cheat_detected)
```

### Decorator Style
```python
from blacs.sdk.integration import blacs_protected

@blacs_protected("MyGame", protection_level="high")
def game_main_loop():
    # Your game code is now protected
    while game_running:
        update_game()
        render_frame()
```

## 📊 System Requirements

- **OS**: Windows 10/11 (Linux support available)
- **Python**: 3.7 or higher
- **Dependencies**: psutil
- **RAM**: 20MB minimum
- **CPU**: <1% overhead

## 🚫 Stopping BLACS

- **Normal Stop**: Press `Ctrl+C` in the terminal
- **Code Stop**: Call `blacs.disable_protection()` in your code
- **Force Stop**: Close the terminal window

## 📁 Project Structure

```
📁 BLACS/ (Simplified)
├── 📄 config.py                    # Simple configuration
├── 📄 example.py                   # Demo application
├── 📄 README.md                    # Documentation
├── 📄 requirements.txt             # Dependencies
└── 📁 blacs/                       # Core system
    ├── 📄 blacs_system.py          # Main orchestrator
    ├── 📁 core/                    # Core components
    ├── 📁 monitors/                # Detection monitors
    │   ├── 📄 input_monitor.py     # Input detection
    │   ├── 📄 memory_monitor.py    # Memory protection
    │   └── 📄 process_monitor_windows.py # Process detection
    ├── 📁 platform/                # Platform utilities
    └── 📁 sdk/                     # Integration SDK
```

## 🎮 Perfect For

- **Game Developers**: Protect your games from cheaters
- **Software Vendors**: Secure your applications  
- **System Administrators**: Monitor critical systems
- **Anyone**: Protect any software from tampering

---

**Ready to secure your applications? Run `python example.py` and test it with Cheat Engine!**