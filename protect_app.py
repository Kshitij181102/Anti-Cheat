#!/usr/bin/env python3
"""
BLACS Application Protector

Universal application protection system - just provide the application path
and BLACS will protect it with advanced DSLL technology.
"""

import os
import sys
import time
import subprocess
import psutil
import argparse
from pathlib import Path
from blacs.sdk.integration import BLACSIntegration

class ApplicationProtector:
    """Universal application protector with BLACS and DSLL."""
    
    def __init__(self):
        """Initialize the application protector."""
        self.protected_app = None
        self.app_process = None
        self.blacs = None
        self.monitoring = False
    
    def find_process_by_name(self, app_name: str):
        """Find running process by executable name."""
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'].lower() == app_name.lower():
                    return proc.info['pid'], proc.info['name'], proc.info.get('exe', '')
                
                # Also check if the exe path contains the app name
                exe_path = proc.info.get('exe', '')
                if exe_path and app_name.lower() in os.path.basename(exe_path).lower():
                    return proc.info['pid'], proc.info['name'], exe_path
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return None, None, None
    
    def launch_application(self, app_path: str):
        """Launch the application to be protected."""
        try:
            print(f"🚀 Launching application: {app_path}")
            
            # Check if file exists
            if not os.path.exists(app_path):
                print(f"❌ Application not found: {app_path}")
                return None, None
            
            # Launch the application
            process = subprocess.Popen(app_path, shell=True)
            
            # Wait a moment for the process to start
            time.sleep(2)
            
            # Find the launched process
            app_name = os.path.basename(app_path)
            pid, name, exe_path = self.find_process_by_name(app_name)
            
            if pid:
                print(f"✅ Application launched: {name} (PID: {pid})")
                return pid, name
            else:
                print(f"⚠️ Application launched but process not found immediately")
                return process.pid, app_name
                
        except Exception as e:
            print(f"❌ Failed to launch application: {e}")
            return None, None
    
    def protect_application(self, app_path: str, protection_level: str = "high", launch_app: bool = False):
        """Protect an application with BLACS and DSLL."""
        print("🛡️ BLACS Universal Application Protector")
        print("=" * 50)
        
        app_name = os.path.basename(app_path)
        app_pid = None
        
        # Check if application is already running
        existing_pid, existing_name, existing_exe = self.find_process_by_name(app_name)
        
        if existing_pid:
            print(f"📋 Found running application: {existing_name} (PID: {existing_pid})")
            app_pid = existing_pid
            app_name = existing_name
        elif launch_app:
            # Only launch if explicitly requested
            app_pid, app_name = self.launch_application(app_path)
            if not app_pid:
                print("❌ Cannot proceed without a running application")
                return False
        else:
            # Monitor mode - wait for application to start
            print(f"⏳ Monitoring mode: Waiting for {app_name} to start...")
            print(f"📁 Target: {app_path}")
            print(f"🔒 Protection Level: {protection_level.upper()}")
            print(f"🔍 DSLL Technology: READY")
            print()
            
            # Wait for application to start
            while not app_pid:
                app_pid, app_name = self.find_process_by_name(app_name)
                if app_pid:
                    print(f"🚀 Detected {app_name} launch (PID: {app_pid})")
                    break
                time.sleep(1)  # Check every second
        
        # Create BLACS protection
        self.blacs = BLACSIntegration(app_name, "1.0.0")
        
        # Set up violation callback
        def on_threat_detected(violation_data):
            print(f"\n🚨 APPLICATION UNDER ATTACK!")
            print(f"📝 Threat: {violation_data.get('description', 'Unknown threat')}")
            print(f"🎯 Target: {app_name} (PID: {app_pid})")
            print(f"⚡ Response: Threat detected and logged by DSLL")
            print(f"📊 Severity: {violation_data.get('severity', 'unknown').upper()}")
            print("-" * 50)
        
        self.blacs.set_violation_callback("critical", on_threat_detected)
        self.blacs.set_violation_callback("high", on_threat_detected)
        self.blacs.set_violation_callback("medium", on_threat_detected)
        
        try:
            # Enable BLACS protection with DSLL
            if self.blacs.enable_protection(protection_level):
                print(f"\n✅ {app_name} is now protected by BLACS with DSLL!")
                print(f"🎯 Protected Application: {app_name} (PID: {app_pid})")
                print(f"📁 Application Path: {app_path}")
                
                # Add application to DSLL protection
                self.blacs.blacs_system.add_protected_process(app_pid)
                
                # Show protection status
                status = self.blacs.get_protection_status()
                print(f"\n📊 Protection Status:")
                print(f"   • Application: {status['app_name']}")
                print(f"   • Protection Level: {status['protection_level'].upper()}")
                print(f"   • DSLL Technology: {status['dsll_technology'].upper()}")
                
                # Show DSLL statistics
                dsll_stats = self.blacs.get_dsll_statistics()
                if "error" not in dsll_stats:
                    print(f"   • DSLL Monitoring: ACTIVE")
                    print(f"   • Protected Processes: {dsll_stats.get('protected_processes', 0)}")
                
                # Show system status
                system_status = status.get('system_status')
                if system_status:
                    print(f"\n🔍 Active Monitors:")
                    monitors = system_status.get('monitors', {})
                    for monitor, info in monitors.items():
                        status_icon = "✅" if info.get('enabled') else "❌"
                        monitor_name = monitor.replace('_', ' ').title()
                        if monitor == "dsll_monitor":
                            print(f"   {status_icon} DSLL Monitor (Revolutionary syscall monitoring)")
                        else:
                            print(f"   {status_icon} {monitor_name}")
                
                print(f"\n🧪 Testing Instructions:")
                print(f"=" * 25)
                print(f"✅ {app_name} is running and protected")
                print(f"🔍 BLACS with DSLL is monitoring for threats")
                print(f"🧪 Try these tests while {app_name} is running:")
                print(f"   • Open Cheat Engine and try to attach")
                print(f"   • Open Process Hacker or Process Explorer")
                print(f"   • Try x64dbg, OllyDbg, or any debugger")
                print(f"   • Use memory editors or injection tools")
                print(f"   • BLACS DSLL will detect and alert instantly!")
                
                print(f"\n⏳ Monitoring {app_name}... (Press Ctrl+C to stop)")
                
                # Start monitoring loop
                self.monitoring = True
                self.monitor_application(app_pid, app_name)
                
                return True
            else:
                print("❌ Failed to enable BLACS protection")
                return False
                
        except KeyboardInterrupt:
            print(f"\n⏹️ Stopping protection for {app_name}...")
            return True
        except Exception as e:
            print(f"❌ Protection error: {e}")
            return False
        finally:
            self.cleanup_protection(app_name)
    
    def monitor_application(self, app_pid: int, app_name: str):
        """Monitor the protected application."""
        monitor_count = 0
        
        while self.monitoring:
            try:
                time.sleep(5)
                monitor_count += 1
                
                # Check if application is still running
                if not psutil.pid_exists(app_pid):
                    print(f"\n⚠️ {app_name} was closed")
                    break
                
                # Show periodic updates every 30 seconds
                if monitor_count % 6 == 0:
                    dsll_stats = self.blacs.get_dsll_statistics()
                    if "error" not in dsll_stats:
                        syscalls = dsll_stats.get('total_syscalls_recorded', 0)
                        patterns = dsll_stats.get('suspicious_patterns_detected', 0)
                        print(f"📊 DSLL Update: {syscalls} syscalls monitored, {patterns} suspicious patterns detected")
                
                # Check for violations
                system_status = self.blacs.get_protection_status().get('system_status', {})
                if system_status:
                    monitors = system_status.get('monitors', {})
                    total_violations = sum(info.get('violations_count', 0) for info in monitors.values())
                    if total_violations > 0:
                        print(f"🚨 Total security violations detected: {total_violations}")
                
            except KeyboardInterrupt:
                print(f"\n⏹️ User requested stop...")
                break
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(1)
    
    def cleanup_protection(self, app_name: str):
        """Clean up protection resources."""
        self.monitoring = False
        
        if self.blacs:
            # Export DSLL ledger
            print(f"\n📝 Exporting DSLL forensic ledger...")
            ledger_filename = f"dsll_protection_log_{app_name}_{int(time.time())}.json"
            if self.blacs.export_dsll_ledger(ledger_filename):
                print(f"✅ DSLL ledger exported: {ledger_filename}")
            
            # Disable protection
            self.blacs.disable_protection()
            print(f"✅ Protection disabled for {app_name}")
        
        print(f"\n🎉 Application protection session completed!")

def main():
    """Main function for command line usage."""
    parser = argparse.ArgumentParser(
        description="BLACS Universal Application Protector with DSLL Technology",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python protect_app.py "C:\\Windows\\System32\\calc.exe"
  python protect_app.py "C:\\Windows\\System32\\notepad.exe" --level maximum
  python protect_app.py "C:\\Program Files\\MyGame\\game.exe" --no-launch
  python protect_app.py notepad.exe --level high
        """
    )
    
    parser.add_argument(
        "app_path",
        help="Path to the application executable or just the executable name"
    )
    
    parser.add_argument(
        "--level", "-l",
        choices=["low", "medium", "high", "maximum"],
        default="high",
        help="Protection level (default: high)"
    )
    
    parser.add_argument(
        "--launch",
        action="store_true",
        help="Launch the application (default: monitor mode - wait for application to start)"
    )
    
    args = parser.parse_args()
    
    # Handle relative paths and executable names
    app_path = args.app_path
    
    # If it's just an executable name, try to find it in common locations
    if not os.path.exists(app_path) and not os.path.sep in app_path:
        common_paths = [
            f"C:\\Windows\\System32\\{app_path}",
            f"C:\\Windows\\{app_path}",
            f"C:\\Program Files\\{app_path}",
            f"C:\\Program Files (x86)\\{app_path}"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                app_path = path
                break
        else:
            # If still not found, keep the original path
            pass
    
    # Create protector and run
    protector = ApplicationProtector()
    success = protector.protect_application(
        app_path, 
        args.level, 
        launch_app=args.launch
    )
    
    if success:
        print("\n✅ Protection session completed successfully!")
    else:
        print("\n❌ Protection session failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()