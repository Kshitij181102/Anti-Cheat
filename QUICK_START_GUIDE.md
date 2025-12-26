# 🚀 BLACS Quick Start Guide

## 📋 5-Minute Setup

### Step 1: Install Dependencies (30 seconds)
```bash
pip install psutil
```

### Step 2: Test BLACS (2 minutes)
```bash
python example.py
```
- Choose option 2 (protect specific process)
- Enter "calc" or "calculator"
- Open Calculator app
- Open Cheat Engine and try to attach to Calculator
- **Watch BLACS detect and terminate Cheat Engine instantly!**

### Step 3: Integrate into Your App (2 minutes)
```python
from blacs.sdk import BLACSIntegration

# Add these 3 lines to your application
blacs = BLACSIntegration("MyApp")
blacs.enable_protection("high")
# Your app code here...
blacs.disable_protection()  # On shutdown
```

**That's it! Your application is now protected!**

---

## 🎯 Integration Methods

### Method 1: Direct Integration (Recommended)
```python
from blacs.sdk import BLACSIntegration

def main():
    # Initialize protection
    blacs = BLACSIntegration("MyApplication", "1.0.0")
    
    # Set up cheat detection callback
    def on_cheat_detected(violation_data):
        print(f"🚨 CHEAT DETECTED: {violation_data['description']}")
        # Take action: close app, ban user, log event, etc.
    
    blacs.set_violation_callback("critical", on_cheat_detected)
    
    # Enable protection
    if blacs.enable_protection(protection_level="high"):
        print("✅ BLACS protection enabled")
        
        try:
            # Your application logic here
            run_your_application()
            
        except KeyboardInterrupt:
            print("⏹️ Application stopping...")
        
        finally:
            # Clean shutdown
            blacs.disable_protection()
            print("✅ BLACS protection disabled")
    else:
        print("❌ Failed to enable BLACS protection")

if __name__ == "__main__":
    main()
```

### Method 2: Decorator (Simplest)
```python
from blacs.sdk import blacs_protected

@blacs_protected("MyGame", protection_level="high")
def game_main_loop():
    """Your game is automatically protected"""
    while game_running:
        update_game()
        render_frame()
        handle_input()
        time.sleep(1/60)  # 60 FPS

# Just call your function - protection is automatic
game_main_loop()
```

### Method 3: Context Manager (For Specific Sections)
```python
from blacs.sdk import BLACSProtection

def critical_operation():
    # Protect only critical sections
    with BLACSProtection("MyApp", "maximum") as protection:
        # This code is protected with maximum security
        process_sensitive_data()
        perform_critical_calculations()
        save_important_results()
    
    # Protection automatically disabled after this block

critical_operation()
```

---

## ⚙️ Configuration Options

### Simple Configuration (config.py)
```python
# Choose your protection level
PROTECTION_LEVEL = "high"  # Options: "low", "medium", "high", "maximum"

# Enable/disable monitors
ENABLE_PROCESS_MONITOR = True   # Detects cheat tools
ENABLE_MEMORY_MONITOR = True    # Detects memory tampering
ENABLE_INPUT_MONITOR = True     # Detects automation/bots

# Advanced settings
AUTO_TERMINATE_THREATS = True   # Automatically kill cheat tools
EXTREME_DETECTION_MODE = True   # Enable advanced detection
SCAN_INTERVAL = 2.0            # Seconds between scans
```

### Protection Levels Explained
| Level | Description | Use Case | False Positives |
|-------|-------------|----------|-----------------|
| **low** | Relaxed detection | Development/Testing | Very Low |
| **medium** | Balanced detection | General Applications | Low |
| **high** | Strict detection | Games/Critical Apps | Medium |
| **maximum** | Extreme sensitivity | High-Security Apps | Higher |

---

## 🧪 Testing Your Integration

### Test 1: Basic Protection Test
```python
from blacs.sdk import BLACSIntegration
import time

def test_basic_protection():
    print("🧪 Testing BLACS Basic Protection")
    
    blacs = BLACSIntegration("TestApp")
    
    if blacs.enable_protection("high"):
        print("✅ Protection enabled")
        print("💡 Try opening Cheat Engine now...")
        
        # Run for 30 seconds
        for i in range(30):
            print(f"⏰ Running... {i+1}/30 seconds")
            time.sleep(1)
        
        blacs.disable_protection()
        print("✅ Test completed")
    else:
        print("❌ Protection failed to start")

test_basic_protection()
```

### Test 2: Violation Callback Test
```python
from blacs.sdk import BLACSIntegration
import time

def test_violation_callbacks():
    print("🧪 Testing BLACS Violation Callbacks")
    
    blacs = BLACSIntegration("TestApp")
    
    # Track violations
    violations_detected = []
    
    def on_critical_violation(violation_data):
        violations_detected.append(("CRITICAL", violation_data))
        print(f"🚨 CRITICAL: {violation_data.get('description', 'Unknown')}")
    
    def on_high_violation(violation_data):
        violations_detected.append(("HIGH", violation_data))
        print(f"⚠️ HIGH: {violation_data.get('description', 'Unknown')}")
    
    # Register callbacks
    blacs.set_violation_callback("critical", on_critical_violation)
    blacs.set_violation_callback("high", on_high_violation)
    
    if blacs.enable_protection("high"):
        print("✅ Protection with callbacks enabled")
        print("💡 Open cheat tools to trigger violations...")
        
        # Monitor for violations
        for i in range(60):
            if violations_detected:
                print(f"📊 Violations detected: {len(violations_detected)}")
            time.sleep(1)
        
        blacs.disable_protection()
        
        # Summary
        print(f"\n📊 Test Summary:")
        print(f"   Total violations: {len(violations_detected)}")
        for severity, violation in violations_detected:
            print(f"   {severity}: {violation.get('description', 'Unknown')}")
    
    print("✅ Callback test completed")

test_violation_callbacks()
```

### Test 3: Performance Impact Test
```python
import time
import psutil
from blacs.sdk import BLACSIntegration

def test_performance_impact():
    print("🧪 Testing BLACS Performance Impact")
    
    # Measure baseline performance
    process = psutil.Process()
    baseline_cpu = process.cpu_percent(interval=1)
    baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    print(f"📊 Baseline - CPU: {baseline_cpu:.1f}%, Memory: {baseline_memory:.1f}MB")
    
    # Enable BLACS protection
    blacs = BLACSIntegration("PerformanceTest")
    blacs.enable_protection("high")
    
    # Measure with BLACS
    time.sleep(2)  # Let it stabilize
    protected_cpu = process.cpu_percent(interval=5)
    protected_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    print(f"📊 With BLACS - CPU: {protected_cpu:.1f}%, Memory: {protected_memory:.1f}MB")
    
    # Calculate impact
    cpu_impact = protected_cpu - baseline_cpu
    memory_impact = protected_memory - baseline_memory
    
    print(f"📈 Impact - CPU: +{cpu_impact:.1f}%, Memory: +{memory_impact:.1f}MB")
    
    blacs.disable_protection()
    print("✅ Performance test completed")

test_performance_impact()
```

---

## 🎮 Real-World Examples

### Example 1: Protecting a Python Game
```python
import pygame
from blacs.sdk import BLACSIntegration

class ProtectedGame:
    def __init__(self):
        # Initialize BLACS protection
        self.blacs = BLACSIntegration("MyPythonGame", "1.0.0")
        self.setup_protection()
        
        # Initialize pygame
        pygame.init()
        self.screen = pygame.display.set_mode((800, 600))
        self.clock = pygame.time.Clock()
        self.running = True
    
    def setup_protection(self):
        def on_cheat_detected(violation_data):
            print(f"🚨 CHEAT DETECTED: {violation_data['description']}")
            # In a real game, you might:
            # - Show warning message
            # - Save game state
            # - Report to server
            # - Close game
            self.handle_cheat_detection()
        
        self.blacs.set_violation_callback("critical", on_cheat_detected)
        
        if self.blacs.enable_protection("high"):
            print("✅ Game protection enabled")
        else:
            print("⚠️ Game protection failed - continuing without protection")
    
    def handle_cheat_detection(self):
        # Show warning to player
        print("⚠️ Cheating detected! Game will close in 5 seconds...")
        pygame.time.wait(5000)
        self.running = False
    
    def run(self):
        while self.running:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.running = False
            
            # Game logic here
            self.screen.fill((0, 0, 0))
            pygame.display.flip()
            self.clock.tick(60)
        
        # Clean shutdown
        self.blacs.disable_protection()
        pygame.quit()

# Run the protected game
if __name__ == "__main__":
    game = ProtectedGame()
    game.run()
```

### Example 2: Protecting a Web Application
```python
from flask import Flask, request, jsonify
from blacs.sdk import BLACSIntegration

app = Flask(__name__)

# Initialize BLACS protection for web app
blacs = BLACSIntegration("MyWebApp", "2.0.0")

def setup_web_protection():
    def on_security_violation(violation_data):
        # Log security event
        print(f"🚨 Security violation in web app: {violation_data['description']}")
        # Could also:
        # - Log to security system
        # - Alert administrators
        # - Block suspicious IPs
        # - Increase monitoring
    
    blacs.set_violation_callback("critical", on_security_violation)
    blacs.set_violation_callback("high", on_security_violation)
    
    return blacs.enable_protection("high")

@app.route('/api/sensitive-operation', methods=['POST'])
def sensitive_operation():
    # This endpoint is protected by BLACS
    data = request.get_json()
    
    # Process sensitive data
    result = process_sensitive_data(data)
    
    return jsonify({"result": result, "protected": True})

def process_sensitive_data(data):
    # Your sensitive business logic here
    return {"processed": True, "timestamp": time.time()}

if __name__ == "__main__":
    if setup_web_protection():
        print("✅ Web application protection enabled")
        app.run(debug=False, host='0.0.0.0', port=5000)
    else:
        print("❌ Failed to enable protection")
```

### Example 3: Protecting a Desktop Application
```python
import tkinter as tk
from tkinter import messagebox
from blacs.sdk import BLACSIntegration

class ProtectedDesktopApp:
    def __init__(self):
        # Initialize BLACS
        self.blacs = BLACSIntegration("MyDesktopApp", "1.5.0")
        self.setup_protection()
        
        # Create GUI
        self.root = tk.Tk()
        self.root.title("Protected Desktop Application")
        self.root.geometry("400x300")
        
        # Add protection status indicator
        self.status_label = tk.Label(
            self.root, 
            text="🛡️ BLACS Protection: ACTIVE", 
            fg="green", 
            font=("Arial", 12, "bold")
        )
        self.status_label.pack(pady=10)
        
        # Your app widgets here
        self.create_widgets()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_protection(self):
        def on_cheat_attempt(violation_data):
            # Show warning dialog
            messagebox.showerror(
                "Security Alert", 
                f"Cheating attempt detected!\n\n{violation_data['description']}\n\nApplication will close for security."
            )
            self.root.quit()
        
        self.blacs.set_violation_callback("critical", on_cheat_attempt)
        
        if self.blacs.enable_protection("high"):
            print("✅ Desktop app protection enabled")
        else:
            print("⚠️ Protection failed")
            self.status_label.config(text="⚠️ BLACS Protection: FAILED", fg="red")
    
    def create_widgets(self):
        # Your application widgets
        tk.Label(self.root, text="This is a protected desktop application").pack(pady=20)
        
        tk.Button(
            self.root, 
            text="Perform Sensitive Operation", 
            command=self.sensitive_operation
        ).pack(pady=10)
        
        tk.Button(
            self.root, 
            text="Check Protection Status", 
            command=self.check_status
        ).pack(pady=10)
    
    def sensitive_operation(self):
        # This operation is protected by BLACS
        messagebox.showinfo("Success", "Sensitive operation completed safely!")
    
    def check_status(self):
        status = self.blacs.get_protection_status()
        messagebox.showinfo(
            "Protection Status", 
            f"App: {status['app_name']}\n"
            f"Protected: {status['is_protected']}\n"
            f"Level: {status['protection_level']}\n"
            f"PID: {status['app_pid']}"
        )
    
    def on_closing(self):
        # Clean shutdown
        self.blacs.disable_protection()
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()

# Run the protected desktop app
if __name__ == "__main__":
    app = ProtectedDesktopApp()
    app.run()
```

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue 1: "Failed to enable BLACS protection"
**Solution:**
```python
# Check if psutil is installed
try:
    import psutil
    print("✅ psutil is available")
except ImportError:
    print("❌ Install psutil: pip install psutil")

# Check if config is accessible
try:
    import config
    print(f"✅ Config loaded: {config.PROTECTION_LEVEL}")
except ImportError:
    print("❌ config.py not found or has errors")
```

#### Issue 2: High false positive rate
**Solution:**
```python
# Lower the protection level
# In config.py:
PROTECTION_LEVEL = "low"  # Instead of "high" or "maximum"

# Or disable specific monitors
ENABLE_INPUT_MONITOR = False  # If getting input false positives
```

#### Issue 3: Performance impact too high
**Solution:**
```python
# Increase scan interval
# In config.py:
SCAN_INTERVAL = 5.0  # Instead of 2.0 (scan every 5 seconds)

# Disable extreme detection
EXTREME_DETECTION_MODE = False
```

#### Issue 4: Not detecting specific cheat tool
**Solution:**
```python
# Add custom signature to process monitor
# Edit blacs/monitors/process_monitor_windows.py
# Add your cheat tool name to suspicious_names set:
self.suspicious_names.add("your_cheat_tool_name")
```

---

## 📞 Support

### Getting Help
- 📖 **Documentation**: Read `README.md` and `FEATURES_AND_COMPARISON.md`
- 🧪 **Test First**: Run `python example.py` to verify setup
- 🔧 **Check Config**: Verify `config.py` settings
- 📝 **Check Logs**: Look for error messages in console output

### Reporting Issues
When reporting issues, please include:
1. **Python version**: `python --version`
2. **Operating system**: Windows/Linux version
3. **BLACS configuration**: Your `config.py` settings
4. **Error messages**: Full error output
5. **Steps to reproduce**: What you were doing when the issue occurred

---

**🎉 Congratulations! You now know how to use BLACS to protect any application from cheating attempts. Start with the simple examples and gradually add more advanced features as needed.**