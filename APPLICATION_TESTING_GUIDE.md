# 🛡️ BLACS Application Testing Guide

Complete guide for protecting and testing any Windows application with BLACS and DSLL technology.

## 🚀 Quick Start - Protect Any Application

### Method 1: Using the Universal Protector (Recommended)

```bash
# Protect Calculator
python protect_app.py "C:\Windows\System32\calc.exe"

# Protect Notepad with maximum security
python protect_app.py "C:\Windows\System32\notepad.exe" --level maximum

# Protect any game or application
python protect_app.py "C:\Program Files\MyGame\game.exe" --level high

# Just use executable name (auto-finds common locations)
python protect_app.py calc.exe
python protect_app.py notepad.exe
```

### Method 2: Using the CLI Module

```bash
# Basic protection
python -m blacs.cli protect "C:\Windows\System32\calc.exe"

# Advanced protection
python -m blacs.cli protect "C:\Program Files\MyApp\app.exe" --level maximum
```

### Method 3: Using Batch Script (Windows)

```batch
# Simple protection
protect.bat "C:\Windows\System32\calc.exe" high

# Game protection
protect.bat "C:\Program Files\Steam\steamapps\common\MyGame\game.exe" maximum
```

## 🎯 Testing Different Applications

### 1. System Applications

#### Windows Calculator
```bash
python protect_app.py calc.exe --level high
```
**What to test:**
- Open Cheat Engine → Try to attach to Calculator
- Use Process Hacker → Try to modify Calculator memory
- Try x64dbg → Attempt to debug Calculator process

#### Notepad
```bash
python protect_app.py notepad.exe --level medium
```
**What to test:**
- Memory editors trying to modify text buffer
- Process injection attempts
- Automation tools trying to control input

#### Paint
```bash
python protect_app.py "C:\Windows\System32\mspaint.exe"
```
**What to test:**
- Graphics memory manipulation
- Drawing automation detection
- Process tampering attempts

### 2. Games and Entertainment

#### Steam Games
```bash
python protect_app.py "C:\Program Files (x86)\Steam\steamapps\common\GameName\game.exe" --level maximum
```

#### Epic Games
```bash
python protect_app.py "C:\Program Files\Epic Games\GameName\game.exe" --level high
```

#### Standalone Games
```bash
python protect_app.py "C:\Games\MyGame\game.exe" --level high
```

**What to test with games:**
- Speed hacks and time manipulation
- Memory trainers and cheat tables
- Aim bots and automation tools
- Graphics overlays and ESP cheats

### 3. Productivity Applications

#### Microsoft Office
```bash
python protect_app.py "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
```

#### Web Browsers
```bash
python protect_app.py "C:\Program Files\Google\Chrome\Application\chrome.exe"
python protect_app.py "C:\Program Files\Mozilla Firefox\firefox.exe"
```

#### Development Tools
```bash
python protect_app.py "C:\Program Files\Microsoft VS Code\Code.exe"
python protect_app.py "C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe"
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

#### Analyze the Ledger
```python
import json

# Load the exported ledger
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

### Custom Protection Levels
Edit `config.py` before testing:

```python
# For intensive testing
PROTECTION_LEVEL = "maximum"
ENABLE_DSLL_MONITOR = True
DSLL_CONFIG = {
    "monitor_interval": 0.05,  # 50ms for ultra-sensitive detection
    "ledger_max_size": 50000,  # Larger ledger for comprehensive logging
}
```

### Testing-Specific Settings
```python
# Enable all monitors for comprehensive testing
ENABLE_INPUT_MONITOR = True
ENABLE_PROCESS_MONITOR = True
ENABLE_MEMORY_MONITOR = True
ENABLE_DSLL_MONITOR = True

# Aggressive detection thresholds
MAX_HUMAN_FREQUENCY = 5.0  # Very low for testing
AUTOMATION_THRESHOLD = 0.3  # Very sensitive
AUTO_TERMINATE_THREATS = True
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
2. **Adjust Thresholds**: Edit `config.py` to reduce sensitivity
3. **Whitelist Processes**: Modify process monitor to ignore specific tools

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