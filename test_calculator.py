#!/usr/bin/env python3
"""
BLACS Calculator Protection Test

This script demonstrates how to protect the Windows Calculator app
with BLACS anti-cheat system and test it against cheat tools.
"""

import time
import subprocess
import psutil
import os
from blacs.sdk.integration import BLACSIntegration

def find_calculator_process():
    """Find running Calculator process."""
    calc_names = ["Calculator.exe", "calc.exe", "WindowsCalculator.exe"]
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in calc_names:
                return proc.info['pid'], proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return None, None

def launch_calculator():
    """Launch Windows Calculator."""
    try:
        print("🧮 Launching Windows Calculator...")
        # Try different ways to launch calculator
        try:
            subprocess.Popen("calc.exe", shell=True)
        except:
            subprocess.Popen("calculator:", shell=True)
        
        # Wait for calculator to start
        time.sleep(2)
        
        pid, name = find_calculator_process()
        if pid:
            print(f"✅ Calculator launched: {name} (PID: {pid})")
            return pid, name
        else:
            print("❌ Calculator not found after launch")
            return None, None
            
    except Exception as e:
        print(f"❌ Failed to launch calculator: {e}")
        return None, None

def test_calculator_protection():
    """Test BLACS protection on Calculator app."""
    print("🛡️  BLACS Calculator Protection Test")
    print("=" * 45)
    
    # Launch calculator
    calc_pid, calc_name = launch_calculator()
    if not calc_pid:
        print("❌ Cannot proceed without Calculator running")
        return
    
    # Create BLACS protection for Calculator
    blacs = BLACSIntegration("WindowsCalculator", "1.0.0")
    
    # Set up violation callback
    def on_calculator_threat(violation_data):
        print(f"\n🚨 CALCULATOR UNDER ATTACK!")
        print(f"📝 Threat: {violation_data.get('description', 'Unknown')}")
        print(f"🎯 Target: Calculator (PID: {calc_pid})")
        print(f"⚡ Response: Threat detected and logged")
        print("-" * 40)
    
    blacs.set_violation_callback("critical", on_calculator_threat)
    blacs.set_violation_callback("high", on_calculator_threat)
    
    try:
        # Enable BLACS protection
        if blacs.enable_protection("high"):
            print(f"\n✅ Calculator is now protected by BLACS!")
            print(f"🎯 Protected Process: {calc_name} (PID: {calc_pid})")
            
            # Add calculator to DSLL protection
            blacs.blacs_system.add_protected_process(calc_pid)
            
            # Show protection status
            status = blacs.get_protection_status()
            print(f"\n📊 Protection Status:")
            print(f"   • DSLL Technology: {status['dsll_technology'].upper()}")
            print(f"   • Protection Level: {status['protection_level'].upper()}")
            
            # Show DSLL stats
            dsll_stats = blacs.get_dsll_statistics()
            if "error" not in dsll_stats:
                print(f"   • DSLL Monitoring: ACTIVE")
                print(f"   • Protected Processes: {dsll_stats.get('protected_processes', 0)}")
            
            print(f"\n🧪 Testing Instructions:")
            print(f"=" * 25)
            print(f"1. ✅ Calculator is running and protected")
            print(f"2. 🔍 BLACS is monitoring Calculator for threats")
            print(f"3. 🧪 Now try these tests:")
            print(f"   • Open Cheat Engine")
            print(f"   • Try to attach to Calculator process")
            print(f"   • Open Process Hacker")
            print(f"   • Try x64dbg or any debugger")
            print(f"   • BLACS will detect and alert!")
            
            print(f"\n⏳ Monitoring Calculator... (Press Ctrl+C to stop)")
            
            # Monitor loop
            monitor_count = 0
            while True:
                time.sleep(5)
                monitor_count += 1
                
                # Check if calculator is still running
                if not psutil.pid_exists(calc_pid):
                    print(f"\n⚠️ Calculator was closed")
                    break
                
                # Show periodic updates
                if monitor_count % 6 == 0:  # Every 30 seconds
                    dsll_stats = blacs.get_dsll_statistics()
                    if "error" not in dsll_stats:
                        syscalls = dsll_stats.get('total_syscalls_recorded', 0)
                        patterns = dsll_stats.get('suspicious_patterns_detected', 0)
                        print(f"📊 DSLL Update: {syscalls} syscalls, {patterns} suspicious patterns")
                
                # Show system status
                system_status = blacs.get_protection_status()['system_status']
                if system_status:
                    monitors = system_status.get('monitors', {})
                    total_violations = sum(info.get('violations_count', 0) for info in monitors.values())
                    if total_violations > 0:
                        print(f"🚨 Total violations detected: {total_violations}")
        
        else:
            print("❌ Failed to enable BLACS protection")
    
    except KeyboardInterrupt:
        print(f"\n⏹️ Stopping Calculator protection test...")
    except Exception as e:
        print(f"❌ Test error: {e}")
    
    finally:
        # Export DSLL ledger
        print(f"\n📝 Exporting DSLL forensic ledger...")
        if blacs.export_dsll_ledger(f"calculator_protection_log_{int(time.time())}.json"):
            print("✅ DSLL ledger exported for analysis")
        
        # Disable protection
        blacs.disable_protection()
        print("✅ Calculator protection disabled")
        
        print(f"\n🎉 Calculator protection test completed!")

def main():
    """Main test function."""
    print("🧪 BLACS Application Protection Test")
    print("🎯 Target: Windows Calculator")
    print("🛡️ Technology: BLACS with DSLL")
    print()
    
    # Check if Calculator is already running
    existing_pid, existing_name = find_calculator_process()
    if existing_pid:
        print(f"📋 Found existing Calculator: {existing_name} (PID: {existing_pid})")
        choice = input("Use existing Calculator? (y/n): ").lower().strip()
        if choice != 'y':
            print("Please close Calculator and run this script again.")
            return
    
    # Run the test
    test_calculator_protection()

if __name__ == "__main__":
    main()