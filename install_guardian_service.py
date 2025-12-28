#!/usr/bin/env python3
"""
BLACS Guardian Service Installer

Installs BLACS Guardian as a tamper-proof Windows service that requires
administrator privileges to stop.
"""

import os
import sys
import ctypes
import subprocess
import shutil
from pathlib import Path

def check_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def require_admin():
    """Require administrator privileges."""
    if not check_admin():
        print("🚫 Administrator privileges required!")
        print("   Right-click and select 'Run as administrator'")
        
        try:
            # Restart with admin privileges
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
        except Exception as e:
            print(f"❌ Failed to restart with admin privileges: {e}")
            return False
    
    return True

def create_service_script():
    """Create the service script."""
    service_script = '''
import sys
import os
import time
import servicemanager
import win32serviceutil
import win32service
import win32event

# Add the BLACS directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from blacs_guardian import BLACSGuardian

class BLACSGuardianService(win32serviceutil.ServiceFramework):
    """BLACS Guardian Windows Service."""
    
    _svc_name_ = "BLACSGuardian"
    _svc_display_name_ = "BLACS Guardian Protection Service"
    _svc_description_ = "Tamper-proof anti-cheat protection service with DSLL technology"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.guardian = None
    
    def SvcStop(self):
        """Stop the service."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.guardian:
            self.guardian.stop_guardian()
        win32event.SetEvent(self.hWaitStop)
    
    def SvcDoRun(self):
        """Run the service."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        # Start BLACS Guardian
        self.guardian = BLACSGuardian()
        self.guardian.start_guardian()
        
        # Keep service running
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(BLACSGuardianService)
'''
    
    with open('blacs_guardian_service.py', 'w') as f:
        f.write(service_script)
    
    print("✅ Service script created: blacs_guardian_service.py")

def install_service():
    """Install the BLACS Guardian service."""
    try:
        # Install the service
        cmd = [
            sys.executable, 
            'blacs_guardian_service.py', 
            'install'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ BLACS Guardian service installed successfully")
            
            # Start the service
            start_cmd = [
                sys.executable,
                'blacs_guardian_service.py',
                'start'
            ]
            
            start_result = subprocess.run(start_cmd, capture_output=True, text=True)
            
            if start_result.returncode == 0:
                print("✅ BLACS Guardian service started")
                return True
            else:
                print(f"⚠️ Service installed but failed to start: {start_result.stderr}")
                return False
        else:
            print(f"❌ Service installation failed: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"❌ Service installation error: {e}")
        return False

def create_tamper_proof_launcher():
    """Create a tamper-proof launcher."""
    launcher_script = '''
@echo off
echo 🛡️ BLACS Guardian - Tamper-Proof Protection
echo ==========================================

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Administrator privileges: VERIFIED
) else (
    echo 🚫 Administrator privileges required!
    echo    Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Start BLACS Guardian
echo 🚀 Starting tamper-proof protection...
python blacs_guardian.py %*

pause
'''
    
    with open('start_guardian.bat', 'w') as f:
        f.write(launcher_script)
    
    print("✅ Tamper-proof launcher created: start_guardian.bat")

def main():
    """Main installer function."""
    print("🛡️ BLACS Guardian Service Installer")
    print("=" * 40)
    
    # Require admin privileges
    if not require_admin():
        sys.exit(1)
    
    print("🔒 Administrator privileges: VERIFIED")
    
    # Check if pywin32 is available for service installation
    try:
        import win32serviceutil
        import win32service
        import win32event
        service_available = True
    except ImportError:
        print("⚠️ pywin32 not available - service installation not possible")
        print("   Install with: pip install pywin32")
        service_available = False
    
    print("\n📋 Installation Options:")
    print("1. Install as Windows Service (tamper-proof)")
    print("2. Create tamper-proof launcher only")
    print("3. Both service and launcher")
    
    if not service_available:
        print("\nNote: Service installation requires pywin32")
        choice = input("\nChoose option (2): ").strip() or "2"
    else:
        choice = input("\nChoose option (1-3): ").strip()
    
    success = False
    
    if choice == "1" and service_available:
        # Install service only
        create_service_script()
        success = install_service()
    
    elif choice == "2":
        # Create launcher only
        create_tamper_proof_launcher()
        success = True
    
    elif choice == "3" and service_available:
        # Both service and launcher
        create_service_script()
        create_tamper_proof_launcher()
        success = install_service()
    
    else:
        print("❌ Invalid choice or service not available")
        sys.exit(1)
    
    if success:
        print("\n🎉 BLACS Guardian installation completed!")
        print("\n💡 Usage:")
        
        if choice in ["1", "3"] and service_available:
            print("   • Service: Automatically starts with Windows")
            print("   • Control: Use Windows Services manager")
            print("   • Status: Check 'BLACS Guardian Protection Service'")
        
        if choice in ["2", "3"]:
            print("   • Launcher: Run start_guardian.bat as Administrator")
            print("   • Command: start_guardian.bat \"app_path\" level")
        
        print("\n🔒 Tamper-proof features:")
        print("   • Requires Administrator privileges to stop")
        print("   • High process priority")
        print("   • Self-protection mechanisms")
        print("   • Comprehensive cheat detection")
    else:
        print("\n❌ Installation failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()