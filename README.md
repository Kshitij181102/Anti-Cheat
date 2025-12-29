# BLACS Guardian v2.0 - Advanced Anti-Cheat System

**Revolutionary tamper-resistant anti-cheat protection with DSLL technology and comprehensive logging**

## 🚀 Key Features

### 🛡️ **Tamper-Proof Protection**
- **Administrator-only operation** - Cannot be stopped without admin privileges
- **Safe tamper-resistance** - No BSOD functionality, system-safe operation
- **High process priority** - Maintains priority for continuous monitoring
- **Graceful shutdown** - Safe termination without system crashes

### 🔍 **Revolutionary DSLL Technology**
- **Deterministic Syscall Lockstep Ledger** - Real-time syscall monitoring
- **Cryptographic verification** - Ensures data integrity
- **Behavioral pattern analysis** - Detects injection attempts
- **Forensic ledger** - Complete audit trail for analysis
- **External tool detection** - Monitors Process Explorer, CheatEngine interactions

### 📊 **Comprehensive Logging System**
- **6 specialized log files** - Categorized event logging
- **JSON structured logs** - Machine-readable forensic data
- **Real-time monitoring** - All processes tracked and logged
- **Threat intelligence** - Detailed attack pattern analysis
- **Performance metrics** - System impact monitoring

### 🎯 **Universal Application Protection**
- **Any Windows application** - Protect games, software, utilities
- **Relaunch detection** - Automatically protects relaunched applications
- **PID lifecycle tracking** - Handles process restarts seamlessly
- **Multi-application support** - Protect multiple apps simultaneously
- **Windows app compatibility** - Supports UWP and legacy applications

### ⚙️ **Advanced Configuration System**
- **Single JSON configuration** - All settings in blacs_config.json
- **5 protection levels** - Safe, Low, Medium, High, Maximum
- **500+ threat signatures** - Comprehensive cheat tool database
- **Granular control** - Fine-tune detection thresholds and responses

## 🔧 **Protection Levels**

| Level | Description | Auto-Terminate | DSLL | Scan Interval | Use Case |
|-------|-------------|----------------|------|---------------|----------|
| **Safe** | Ultra-safe, only obvious cheat tools | ❌ | ✅ | 5s | Development/Testing |
| **Low** | Basic protection for development | ❌ | ❌ | 5s | Low-risk environments |
| **Medium** | Balanced protection for general use | ❌ | ✅ | 3s | General applications |
| **High** | Strict protection with termination | ✅ | ✅ | 2s | Important applications |
| **Maximum** | Extreme protection, very aggressive | ✅ | ✅ | 1s | Critical applications |

## 🚀 **Quick Start**

### **Requirements**
- Windows 10/11
- Python 3.8+
- Administrator privileges
- psutil library

### **Installation**
```bash
# Install dependencies
pip install -r requirements.txt

# Run BLACS Guardian (requires admin)
python blacs_guardian.py "C:\Windows\System32\calc.exe" --level safe
```

### **Example Usage**
```bash
# Protect Calculator with safe mode (no termination)
python blacs_guardian.py "C:\Windows\System32\calc.exe" --level safe

# Protect Notepad with high security (auto-terminate threats)
python blacs_guardian.py "C:\Windows\System32\notepad.exe" --level high

# Protect any application with maximum security
python blacs_guardian.py "C:\Program Files\MyGame\game.exe" --level maximum
```

## 🔍 **How It Works**

### **1. Launch Protection**
```bash
python blacs_guardian.py "C:\Windows\System32\calc.exe" --level safe
```

### **2. Automatic Detection**
- BLACS monitors for Calculator launch
- When detected, protection activates automatically
- All processes logged, only confirmed cheat tools terminated

### **3. Relaunch Support**
- Close Calculator and reopen it
- BLACS automatically detects the new instance (new PID)
- Protection seamlessly transfers to new process

### **4. Multi-Layer Monitoring**
- **Process Monitor**: Scans for 500+ cheat tool signatures
- **Memory Monitor**: Prevents external memory access
- **DSLL Technology**: Advanced syscall monitoring and behavioral analysis
- **Input Monitor**: Detects automation patterns

### **5. DSLL Technology in Action**
- Monitors external tools accessing protected processes
- Detects Process Explorer, CheatEngine, debuggers
- Records critical syscalls (NtOpenProcess, NtReadVirtualMemory)
- Identifies suspicious patterns and injection attempts

## 📋 **What Gets Detected**

### **Cheat Tools (Terminated in High/Maximum levels)**
- **Memory Editors**: CheatEngine, ArtMoney, GameGuardian, MemoryEditor
- **Debuggers**: OllyDbg, x64dbg, x32dbg, Process Hacker, IDA Pro
- **Injection Tools**: DLL injectors, process injectors, code cave tools
- **Speed Hacks**: SpeedHack, GameSpeed, TimeScale, ClockBlocker
- **Trainers**: Game trainers, Fling trainers, MrAntiFun, Wemod
- **Automation Tools**: AutoClicker, AutoHotkey, bots, aimbots
- **Mobile Hacking**: GameGuardian, Lucky Patcher, Freedom, CreHack

### **System Processes (Logged Only)**
- Windows services and system processes
- Legitimate applications and software
- Audio services, Windows Defender
- All background processes for monitoring

### **DSLL Detection Capabilities**
- External tool access to protected processes
- Memory scanning attempts
- Process manipulation syscalls
- Injection and hooking attempts
- Behavioral pattern analysis

## ⚙️ **Configuration**

### **Edit `blacs_config.json`**
```json
{
  "protection_levels": {
    "safe": {
      "auto_terminate": false,
      "dsll_enabled": true,
      "scan_interval": 5.0
    }
  },
  "threat_detection": {
    "signature_database": {
      "memory_editors": ["cheatengine.exe", "artmoney.exe"],
      "debuggers": ["ollydbg.exe", "x64dbg.exe"]
    }
  },
  "dsll_configuration": {
    "enabled": true,
    "critical_syscalls": [
      "NtReadVirtualMemory",
      "NtWriteVirtualMemory", 
      "NtOpenProcess"
    ]
  }
}
```

### **Key Settings**
- `auto_terminate`: Whether to terminate detected threats
- `dsll_enabled`: Enable advanced DSLL syscall monitoring
- `scan_interval`: How often to scan for threats (seconds)
- `critical_syscalls`: Syscalls monitored by DSLL
- `signature_database`: Custom threat signatures by category

## 🛡️ **Security Features**

### **Tamper Resistance**
- **Admin-only operation** - Regular users cannot stop BLACS
- **High process priority** - Maintains system priority
- **Self-protection** - Monitors own integrity
- **Safe shutdown** - No system crashes or BSOD

### **Detection Evasion Prevention**
- **Multiple detection layers** - Hard to bypass
- **Behavioral analysis** - Catches unknown tools
- **Real-time monitoring** - Immediate threat response
- **Forensic logging** - Complete audit trail

## 📊 **Logging & Monitoring**

### **Comprehensive Log Files**
- `blacs_guardian.log` - Main system events and process monitoring
- `blacs_applications.log` - Application lifecycle events
- `blacs_threats.log` - Threat detection and termination events
- `blacs_dsll.log` - Advanced DSLL syscall monitoring
- `blacs_system.log` - System initialization and configuration
- `blacs_process_monitor.log` - Detailed process activity

### **DSLL Forensic Data**
- `guardian_log_[app]_[timestamp].json` - Exported DSLL ledger
- Complete syscall records with verification hashes
- Behavioral pattern analysis results
- Process interaction timeline

### **Log Information**
- Process creation/termination with full details
- Threat detections with signature matching
- Memory access attempts and external tool interactions
- System calls with parameters and return values
- Performance metrics and system health

## 🔧 **Advanced Features**

### **DSLL Technology**
- **Syscall monitoring** - Tracks 15+ critical system calls in real-time
- **Behavioral patterns** - Detects process access, memory scanning, injection attempts
- **Cryptographic verification** - Ensures ledger integrity with verification hashes
- **Forensic ledger** - Complete audit trail with JSON export capability
- **External tool detection** - Monitors Process Explorer, CheatEngine interactions
- **Automatic cleanup** - Removes records from terminated processes

### **Multi-Application Protection**
```bash
# Protect multiple applications simultaneously
python blacs_guardian.py "C:\Windows\System32\calc.exe" --level high
# Calculator protection active

# In another terminal:
python blacs_guardian.py "C:\Windows\System32\notepad.exe" --level medium
# Both Calculator and Notepad protected
```

### **SDK Integration**
```python
from blacs.sdk.integration import BLACSIntegration

# Easy integration for developers
blacs = BLACSIntegration("MyApp", "1.0.0")
blacs.enable_protection("high")

# Get DSLL statistics
stats = blacs.get_dsll_statistics()
print(f"Syscalls recorded: {stats['total_syscalls_recorded']}")
```

## 🚨 **Troubleshooting**

### **Common Issues**

**"Access Denied" Error**
- Solution: Run as Administrator (right-click → "Run as administrator")

**"Invalid protection level 'safe'"**
- Solution: Use: `--level safe` (available: safe, low, medium, high, maximum)

**Application not detected after relaunch**
- Solution: Fixed in v2.0 - automatic relaunch detection with PID tracking

**Too many false positives**
- Solution: Use `--level safe` or edit threat signatures in `blacs_config.json`

**DSLL not logging syscalls**
- Solution: Ensure `dsll_enabled: true` in protection level configuration
- Test with Process Explorer accessing protected application

**System crashes or BSOD**
- Solution: BSOD functionality permanently disabled in v2.0 for safety

### **Testing DSLL Functionality**
1. Start BLACS with Calculator: `python blacs_guardian.py calc.exe --level high`
2. Open Calculator application
3. Open Process Explorer and browse to Calculator process
4. Check `blacs_dsll.log` for syscall detection logs
5. DSLL will detect Process Explorer accessing Calculator

## 📈 **Performance**

- **CPU Usage**: < 5% (configurable in blacs_config.json)
- **Memory Usage**: < 100MB (optimized for efficiency)
- **Scan Frequency**: 1-5 seconds (protection level dependent)
- **Detection Speed**: < 200ms for known threats
- **Log File Sizes**: Managed with automatic rotation
- **DSLL Overhead**: < 0.1s monitoring interval for real-time detection

## 🔒 **What Makes BLACS Different**

### **vs. Traditional Anti-Cheat (BattlEye, EAC, VAC)**
- ✅ **Universal**: Works with any Windows application, not game-specific
- ✅ **Tamper-proof**: Cannot be stopped by regular users
- ✅ **Comprehensive logging**: 6 specialized log files with forensic data
- ✅ **DSLL technology**: Revolutionary syscall monitoring and behavioral analysis
- ✅ **Safe operation**: No BSOD or system crashes, graceful shutdown
- ✅ **Real-time protection**: Immediate threat response vs delayed bans

### **vs. Game-Specific Solutions**
- ✅ **Application agnostic**: Protect any Windows app (games, software, utilities)
- ✅ **Relaunch detection**: Handles app restarts with PID tracking
- ✅ **Admin protection**: Requires administrator privileges to stop
- ✅ **Precise detection**: Only terminates confirmed threats, logs everything else
- ✅ **External tool monitoring**: Detects tools accessing protected processes

### **Unique DSLL Advantages**
- ✅ **Syscall ledger**: Cryptographically verified audit trail
- ✅ **Behavioral analysis**: Detects unknown attack patterns
- ✅ **Forensic export**: JSON format for detailed analysis
- ✅ **Real-time monitoring**: 0.1s interval for immediate detection

## 📞 **Support**

For issues or questions:
1. Check the troubleshooting section above
2. Review the `blacs_config.json` configuration
3. Check log files for detailed information
4. Ensure running with Administrator privileges

---

**BLACS Guardian v2.0** - The most advanced, tamper-resistant anti-cheat system for Windows applications.