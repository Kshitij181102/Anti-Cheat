# 🛡️ BLACS Guardian Testing Guide

Complete guide for testing applications with BLACS Guardian tamper-proof protection system.

## 🚀 Quick Start - Tamper-Proof Testing

### Primary Method: BLACS Guardian (Requires Admin)

```bash
# Protect Calculator (requires Administrator privileges)
python blacs_guardian.py "C:\Windows\System32\calc.exe" --level high

# Protect Notepad with maximum security
python blacs_guardian.py "C:\Windows\System32\notepad.exe" --level maximum

# Protect any game or application
python blacs_guardian.py "C:\Program Files\MyGame\game.exe" --level maximum

# Just use executable name (auto-finds common locations)
python blacs_guardian.py calc.exe --level high
```

### Using Batch Script (Windows)

```batch
# Simple tamper-proof protection
protect.bat calc.exe high

# Game protection
protect.bat "C:\Program Files\Steam\steamapps\common\MyGame\game.exe" maximum
```

### Using CLI Module

```bash
# Basic protection via CLI
python -m blacs.cli protect calc.exe --level high

# Advanced protection
python -m blacs.cli protect "C:\Program Files\MyApp\app.exe" --level maximum
```

## 🎯 Testing Different Applications

### 1. System Applications (Requires Admin)

#### Windows Calculator
```bash
python blacs_guardian.py calc.exe --level high
```
**What to test:**
- Open Cheat Engine → Try to attach to Calculator
- Use Process Hacker → Try to modify Calculator memory
- Try x64dbg → Attempt to debug Calculator process

#### Notepad
```bash
python blacs_guardian.py notepad.exe --level medium
```
**What to test:**
- Memory editors trying to modify text buffer
- Process injection attempts
- Automation tools trying to control input

#### Paint
```bash
python blacs_guardian.py "C:\Windows\System32\mspaint.exe" --level high
```
**What to test:**
- Graphics memory manipulation
- Drawing automation detection
- Process tampering attempts

### 2. Games and Entertainment

#### Steam Games
```bash
python blacs_guardian.py "C:\Program Files (x86)\Steam\steamapps\common\GameName\game.exe" --level maximum
```

#### Epic Games
```bash
python blacs_guardian.py "C:\Program Files\Epic Games\GameName\game.exe" --level high
```

#### Standalone Games
```bash
python blacs_guardian.py "C:\Games\MyGame\game.exe" --level high
```

**What to test with games:**
- Speed hacks and time manipulation
- Memory trainers and cheat tables
- Aim bots and automation tools
- Graphics overlays and ESP cheats

### 3. Productivity Applications

#### Microsoft Office
```bash
python blacs_guardian.py "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" --level medium
```

#### Web Browsers
```bash
python blacs_guardian.py "C:\Program Files\Google\Chrome\Application\chrome.exe" --level medium
python blacs_guardian.py "C:\Program Files\Mozilla Firefox\firefox.exe" --level medium
```

#### Development Tools
```bash
python blacs_guardian.py "C:\Program Files\Microsoft VS Code\Code.exe" --level low
python blacs_guardian.py "C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe" --level low
```

## 🧪 Comprehensive Testing Procedures

### Phase 1: Basic Protection Test

1. **Launch Protected Application**
   ```bash
   python protect_app.py "your_app_path" --level high
   ```

2. **Verify Protection Status**
   - Look for "✅ Application is now protected by BLACS with DSLL!"
   - Check that DSLL Technology shows as "ACTIVE"
   - Verify all monitors are enabled

3. **Basic Functionality Test**
   - Use the application normally
   - Ensure no false positives
   - Verify application performance is not affected

### Phase 2: Cheat Tool Detection Test

#### Test with Cheat Engine
1. Start your protected application
2. Open Cheat Engine
3. Try to attach to your application process
4. **Expected Result**: BLACS should detect and alert immediately

#### Test with Process Hacker
1. Open Process Hacker while application is protected
2. Try to access application's memory
3. Attempt to modify process properties
4. **Expected Result**: DSLL should detect suspicious syscalls

#### Test with Debuggers
1. Try x64dbg, OllyDbg, or Visual Studio debugger
2. Attempt to attach to protected process
3. **Expected Result**: Process monitor should detect debugger attachment

### Phase 3: Advanced DSLL Testing

#### Memory Manipulation Detection
```bash
# Run with maximum protection for best DSLL coverage
python protect_app.py "your_app.exe" --level maximum
```

1. Try memory scanning tools
2. Attempt DLL injection
3. Test code cave techniques
4. **Expected Result**: DSLL syscall monitoring should catch all attempts

#### Behavioral Pattern Analysis
1. Run automation tools (AutoHotkey, etc.)
2. Use rapid input generators
3. Try speed manipulation tools
4. **Expected Result**: DSLL pattern analysis should detect abnormal behavior

### Phase 4: Forensic Analysis

#### Export DSLL Ledger
After testing, BLACS automatically exports a forensic ledger:
```
📝 Exporting DSLL forensic ledger...
✅ DSLL ledger exported: dsll_protection_log_AppName_timestamp.json
```

**Note**: These log files are automatically generated during protection sessions and can be safely deleted after analysis. They are not required for the system to function.

#### Analyze the Ledger
```python
import json

# Load the exported ledger (example filename)
with open('dsll_protection_log_AppName_timestamp.json', 'r') as f:
    ledger = json.load(f)

print(f"Total syscalls recorded: {ledger['total_records']}")
print(f"Suspicious patterns: {ledger['statistics']['suspicious_patterns_detected']}")

# Examine individual syscall records
for record in ledger['ledger'][:10]:  # First 10 records
    print(f"Syscall: {record['syscall_name']} from {record['process_name']}")
```

## 🎮 Game-Specific Testing Examples

### Testing FPS Games
```bash
python protect_app.py "C:\Games\FPSGame\game.exe" --level maximum
```
**Test scenarios:**
- Aimbot detection
- Wallhack prevention
- Speed hack detection
- Memory trainer blocking

### Testing Strategy Games
```bash
python protect_app.py "C:\Games\StrategyGame\game.exe" --level high
```
**Test scenarios:**
- Resource manipulation prevention
- Fog of war hack detection
- Unit duplication blocking
- Save game tampering prevention

### Testing Racing Games
```bash
python protect_app.py "C:\Games\RacingGame\game.exe" --level high
```
**Test scenarios:**
- Speed boost detection
- Physics manipulation prevention
- Lap time tampering blocking
- Car stat modification prevention

## 🔧 Advanced Configuration for Testing

### JSON Configuration for Testing
Edit `blacs_config.json` to customize testing settings:

```json
{
  "protection_levels": {
    "testing": {
      "description": "Ultra-sensitive testing configuration",
      "max_human_frequency": 5.0,
      "automation_threshold": 0.3,
      "auto_terminate": true,
      "extreme_detection": true,
      "dsll_enabled": true,
      "scan_interval": 0.5,
      "critical_risk_threshold": 0.7
    }
  },
  "monitors": {
    "dsll_monitor": {
      "enabled": true,
      "settings": {
        "monitor_interval": 0.05,
        "ledger_max_size": 50000,
        "pattern_analysis_window": 100,
        "cryptographic_verification": true
      }
    },
    "process_monitor": {
      "enabled": true,
      "settings": {
        "scan_interval": 1.0,
        "auto_terminate_threats": true,
        "behavioral_analysis": true
      }
    }
  }
}
```

### Configuration Management for Testing
```python
from config_manager import get_config

# Get configuration
config = get_config()

# Enable ultra-sensitive testing mode
config.set("protection_levels.testing.automation_threshold", 0.2)
config.set("monitors.dsll_monitor.settings.monitor_interval", 0.05)
config.save_config()

# Add test-specific signatures
config.add_custom_signature("test_cheat_tool")
config.add_whitelist_process("legitimate_test_app.exe")
```

## 📊 Understanding Test Results

### DSLL Statistics Interpretation
```
📊 DSLL Update: 1,247 syscalls monitored, 3 suspicious patterns detected
```
- **Syscalls Monitored**: Total system calls recorded by DSLL
- **Suspicious Patterns**: Behavioral anomalies detected
- **Higher numbers indicate more thorough monitoring**

### Violation Alerts
```
🚨 APPLICATION UNDER ATTACK!
📝 Threat: Memory manipulation attempt detected
🎯 Target: MyGame.exe (PID: 1234)
⚡ Response: Threat detected and logged by DSLL
📊 Severity: CRITICAL
```

### Monitor Status
```
🔍 Active Monitors:
   ✅ Input Monitor
   ✅ Memory Monitor  
   ✅ Process Monitor Windows
   ✅ DSLL Monitor (Revolutionary syscall monitoring)
```

## 🚨 Troubleshooting Testing Issues

### Application Won't Launch
```bash
# Check if path is correct
python protect_app.py "C:\Full\Path\To\App.exe"

# Try with just executable name
python protect_app.py app.exe

# Use --no-launch if app is already running
python protect_app.py app.exe --no-launch
```

### No Threat Detection
1. **Check Protection Level**: Use `--level maximum` for most sensitive detection
2. **Verify DSLL**: Ensure "DSLL Technology: ACTIVE" appears
3. **Test with Known Tools**: Use Cheat Engine as a baseline test
4. **Check Logs**: Review the exported DSLL ledger for activity

### False Positives
1. **Lower Protection Level**: Try `--level medium` or `--level low`
2. **Adjust Thresholds**: Edit `blacs_config.json` to reduce sensitivity
3. **Whitelist Processes**: Use config manager to add processes to whitelist

### Performance Issues
1. **Reduce DSLL Frequency**: Increase `monitor_interval` in config
2. **Lower Protection Level**: Use `--level medium` instead of maximum
3. **Disable Unnecessary Monitors**: Turn off monitors you don't need for testing

## 🎯 Best Practices for Application Testing

### 1. Start Simple
- Begin with system applications (calc.exe, notepad.exe)
- Use medium protection level initially
- Verify basic functionality before advanced testing

### 2. Gradual Escalation
- Test with simple tools first (Cheat Engine)
- Progress to advanced tools (debuggers, injectors)
- End with sophisticated attack scenarios

### 3. Document Results
- Keep track of what tools are detected
- Note any false positives or missed detections
- Save DSLL ledgers for analysis

### 4. Test Realistic Scenarios
- Use actual cheat tools, not just test programs
- Test during normal application usage
- Verify protection doesn't interfere with legitimate functionality

## 🏆 Success Criteria

Your application is properly protected when:

✅ **BLACS starts successfully** with DSLL active  
✅ **All monitors show as enabled** in status display  
✅ **Cheat Engine detection** triggers immediate alerts  
✅ **DSLL syscall monitoring** records application activity  
✅ **Forensic ledger exports** successfully after session  
✅ **Application performance** remains unaffected  
✅ **No false positives** during normal usage  

---

**🎉 Ready to protect any application? Start with: `python protect_app.py calc.exe`**