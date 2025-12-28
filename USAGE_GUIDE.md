# 🛡️ BLACS Usage Guide - Protect Any Application

Complete guide for using BLACS to protect any Windows application with revolutionary DSLL technology.

## 🚀 Quick Start (3 Easy Ways)

### Method 1: Interactive Launcher (Easiest)
```bash
python blacs_protect.py
```
Follow the prompts to select your application and protection level.

### Method 2: Universal Protector (Recommended)
```bash
# Protect any application by path
python protect_app.py "C:\Windows\System32\calc.exe"

# Or just use the executable name
python protect_app.py calc.exe
```

### Method 3: Batch Script (Windows)
```batch
protect.bat calc.exe high
```

## 📋 Common Applications to Protect

### System Applications
```bash
# Windows Calculator
python protect_app.py calc.exe

# Windows Notepad
python protect_app.py notepad.exe

# Windows Paint
python protect_app.py mspaint.exe

# Command Prompt
python protect_app.py cmd.exe

# PowerShell
python protect_app.py powershell.exe
```

### Web Browsers
```bash
# Google Chrome
python protect_app.py "C:\Program Files\Google\Chrome\Application\chrome.exe"

# Mozilla Firefox
python protect_app.py "C:\Program Files\Mozilla Firefox\firefox.exe"

# Microsoft Edge
python protect_app.py "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
```

### Games
```bash
# Steam games
python protect_app.py "C:\Program Files (x86)\Steam\steamapps\common\GameName\game.exe" --level maximum

# Epic Games
python protect_app.py "C:\Program Files\Epic Games\GameName\game.exe" --level high

# Origin games
python protect_app.py "C:\Program Files (x86)\Origin Games\GameName\game.exe" --level high

# Standalone games
python protect_app.py "C:\Games\MyGame\game.exe" --level maximum
```

### Development Tools
```bash
# Visual Studio Code
python protect_app.py "C:\Program Files\Microsoft VS Code\Code.exe"

# Visual Studio
python protect_app.py "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"

# IntelliJ IDEA
python protect_app.py "C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe"
```

### Office Applications
```bash
# Microsoft Word
python protect_app.py "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"

# Microsoft Excel
python protect_app.py "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"

# Microsoft PowerPoint
python protect_app.py "C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"
```

## 🔒 Protection Levels Explained

### Low Protection
```bash
python protect_app.py myapp.exe --level low
```
- Basic threat detection
- DSLL monitoring disabled
- Minimal performance impact
- Good for testing or low-risk applications

### Medium Protection (Recommended)
```bash
python protect_app.py myapp.exe --level medium
```
- Balanced detection and performance
- DSLL monitoring enabled
- Detects most common threats
- Recommended for general use

### High Protection (Default)
```bash
python protect_app.py myapp.exe --level high
```
- Strict threat detection
- Full DSLL monitoring
- Advanced pattern analysis
- Best for important applications

### Maximum Protection
```bash
python protect_app.py myapp.exe --level maximum
```
- Extreme sensitivity
- Advanced DSLL analysis
- Ultra-fast threat response
- Perfect for games and critical applications

## 🎯 Advanced Usage Options

### Protect Already Running Application
```bash
# Don't launch new instance, protect existing one
python protect_app.py "C:\Windows\System32\calc.exe" --no-launch
```

### Auto-Find Common Applications
```bash
# BLACS will search common locations automatically
python protect_app.py calc.exe
python protect_app.py notepad.exe
python protect_app.py chrome.exe
```

### Using Full Paths
```bash
# Specify exact path for any application
python protect_app.py "C:\Program Files\MyApp\app.exe" --level high
```

## 🧪 Testing Your Protection

### Basic Test
1. Start protection: `python protect_app.py calc.exe`
2. Open Calculator
3. Try opening Cheat Engine
4. Watch BLACS detect the threat!

### Advanced Test
1. Start protection: `python protect_app.py myapp.exe --level maximum`
2. Try various cheat tools:
   - Cheat Engine
   - Process Hacker
   - x64dbg
   - Memory editors
3. All should be detected by DSLL technology

## 📊 Understanding the Output

### Successful Protection Start
```
🛡️ BLACS Universal Application Protector
==================================================
🎯 Protected Application: calc.exe (PID: 1234)
📁 Application Path: C:\Windows\System32\calc.exe

📊 Protection Status:
   • Application: calc.exe
   • Protection Level: HIGH
   • DSLL Technology: ACTIVE
   • DSLL Monitoring: ACTIVE
   • Protected Processes: 1

🔍 Active Monitors:
   ✅ Input Monitor
   ✅ Memory Monitor
   ✅ Process Monitor Windows
   ✅ DSLL Monitor (Revolutionary syscall monitoring)
```

### Threat Detection Alert
```
🚨 APPLICATION UNDER ATTACK!
📝 Threat: Memory manipulation attempt detected
🎯 Target: calc.exe (PID: 1234)
⚡ Response: Threat detected and logged by DSLL
📊 Severity: CRITICAL
--------------------------------------------------
```

### DSLL Statistics
```
📊 DSLL Update: 1,247 syscalls monitored, 3 suspicious patterns detected
```

## 🔧 Troubleshooting

### Application Not Found
```bash
# If you get "Application not found", try:
python protect_app.py "C:\Full\Path\To\Application.exe"

# Or check if the application is in a common location:
python protect_app.py application.exe
```

### Permission Issues
```bash
# Run as administrator if you get permission errors
# Right-click Command Prompt -> "Run as administrator"
python protect_app.py myapp.exe --level high
```

### Application Won't Launch
```bash
# If the application doesn't launch, try protecting an already running instance:
python protect_app.py myapp.exe --no-launch
```

### No Threat Detection
1. Increase protection level: `--level maximum`
2. Verify DSLL is active (should show "DSLL Technology: ACTIVE")
3. Test with known tools like Cheat Engine
4. Check the exported DSLL ledger for activity

## 📝 Forensic Analysis

### Automatic Ledger Export
After each protection session, BLACS automatically exports a forensic ledger:
```
📝 Exporting DSLL forensic ledger...
✅ DSLL ledger exported: dsll_protection_log_calc_1640995200.json
```

### Analyzing the Ledger
```python
import json

# Load the ledger
with open('dsll_protection_log_calc_1640995200.json', 'r') as f:
    data = json.load(f)

print(f"Total syscalls: {data['total_records']}")
print(f"Threats detected: {data['statistics']['suspicious_patterns_detected']}")

# View individual syscall records
for record in data['ledger'][:5]:
    print(f"Syscall: {record['syscall_name']} from {record['process_name']}")
```

## 🎮 Game Protection Examples

### Protect Steam Games
```bash
# Find your Steam games in:
# C:\Program Files (x86)\Steam\steamapps\common\

python protect_app.py "C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\csgo.exe" --level maximum
```

### Protect Epic Games
```bash
# Find your Epic games in:
# C:\Program Files\Epic Games\

python protect_app.py "C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe" --level maximum
```

### Protect Origin Games
```bash
# Find your Origin games in:
# C:\Program Files (x86)\Origin Games\

python protect_app.py "C:\Program Files (x86)\Origin Games\Battlefield V\bfv.exe" --level maximum
```

## 🏆 Best Practices

### 1. Choose the Right Protection Level
- **Games**: Use `maximum` for competitive games
- **Work Apps**: Use `high` for important applications
- **Testing**: Use `medium` for general testing
- **Development**: Use `low` when debugging your own apps

### 2. Test Before Important Use
- Always test protection with your application first
- Verify no false positives occur during normal use
- Check that application performance is acceptable

### 3. Keep Logs for Analysis
- Save the exported DSLL ledgers
- Review them to understand what threats were detected
- Use them for forensic analysis if needed

### 4. Update Regularly
- Keep BLACS updated for latest threat detection
- Update your protection configurations as needed
- Monitor for new cheat tools and techniques

## 🚨 Emergency Procedures

### Stop Protection Immediately
- Press `Ctrl+C` in the terminal
- This will safely stop protection and export logs

### Force Stop
- Close the terminal window
- This will terminate protection immediately

### Restart Protection
- Simply run the protection command again
- BLACS will detect if the application is already running

---

## 🎯 Quick Reference Commands

```bash
# Interactive launcher
python blacs_protect.py

# Protect Calculator
python protect_app.py calc.exe

# Protect with maximum security
python protect_app.py myapp.exe --level maximum

# Protect already running app
python protect_app.py myapp.exe --no-launch

# Use batch script
protect.bat myapp.exe high

# CLI method
python -m blacs.cli protect myapp.exe --level high
```

**🎉 Ready to protect any application? Start with: `python protect_app.py calc.exe`**