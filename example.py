#!/usr/bin/env python3
"""
BLACS Example with Advanced DSLL Technology

Demonstration of BLACS anti-cheat system with revolutionary
DSLL (Deterministic Syscall Lockstep Ledger) monitoring.
"""

import time
import sys
import os
from blacs.sdk.integration import BLACSIntegration

def main():
    """Main example function with DSLL demonstration."""
    print("🛡️  BLACS Anti-Cheat System with DSLL Technology")
    print("=" * 55)
    
    # Create BLACS integration with DSLL
    blacs = BLACSIntegration("ExampleApp", "1.0.0")
    
    try:
        # Enable protection with DSLL
        print("🔄 Enabling BLACS protection with DSLL...")
        if blacs.enable_protection("high"):
            print("✅ BLACS protection with DSLL enabled successfully!")
            
            # Show protection status
            status = blacs.get_protection_status()
            print(f"\n📊 Protection Status:")
            print(f"   • App: {status['app_name']}")
            print(f"   • Version: {status['app_version']}")
            print(f"   • PID: {status['app_pid']}")
            print(f"   • Protected: {status['is_protected']}")
            print(f"   • Level: {status['protection_level']}")
            print(f"   • DSLL Technology: {status['dsll_technology'].upper()}")
            
            # Show system status
            system_status = status.get('system_status')
            if system_status:
                print(f"\n🔍 System Monitoring:")
                monitors = system_status.get('monitors', {})
                for monitor, info in monitors.items():
                    status_icon = "✅" if info.get('enabled') else "❌"
                    violations = info.get('violations_count', 0)
                    
                    if monitor == "dsll_monitor":
                        syscalls = info.get('syscalls_recorded', 0)
                        patterns = info.get('patterns_detected', 0)
                        processes = info.get('protected_processes', 0)
                        print(f"   {status_icon} DSLL Monitor: {violations} violations, {syscalls} syscalls, {patterns} patterns, {processes} processes")
                    else:
                        print(f"   {status_icon} {monitor.replace('_', ' ').title()}: {violations} violations")
            
            # Show DSLL statistics
            dsll_stats = blacs.get_dsll_statistics()
            if "error" not in dsll_stats:
                print(f"\n🔍 DSLL Statistics:")
                print(f"   • Syscalls Recorded: {dsll_stats.get('total_syscalls_recorded', 0)}")
                print(f"   • Patterns Detected: {dsll_stats.get('suspicious_patterns_detected', 0)}")
                print(f"   • Ledger Size: {dsll_stats.get('ledger_size', 0)}")
                print(f"   • Protected Processes: {dsll_stats.get('protected_processes', 0)}")
            
            print(f"\n💡 Advanced Features:")
            print(f"   🔍 DSLL monitors system calls in real-time")
            print(f"   📊 Behavioral pattern analysis active")
            print(f"   🚨 Critical syscall detection enabled")
            print(f"   📝 Forensic ledger recording active")
            
            print(f"\n💡 Try opening Cheat Engine or other cheat tools - DSLL will detect them!")
            print(f"🔄 Simulating protected application activity...")
            
            # Simulate application activity
            for i in range(10):
                print(f"   Processing frame {i+1}/10...")
                time.sleep(1)
                
                # Show periodic DSLL updates
                if i == 4:
                    dsll_stats = blacs.get_dsll_statistics()
                    if "error" not in dsll_stats:
                        print(f"   🔍 DSLL Update: {dsll_stats.get('total_syscalls_recorded', 0)} syscalls recorded")
            
            print(f"\n✅ Application completed successfully!")
            print(f"🛡️  Your application was protected by BLACS with DSLL technology")
            
            # Offer to export DSLL ledger
            export_choice = input(f"\n📝 Export DSLL ledger for analysis? (y/n): ").lower().strip()
            if export_choice == 'y':
                if blacs.export_dsll_ledger():
                    print("✅ DSLL ledger exported successfully!")
                else:
                    print("❌ Failed to export DSLL ledger")
        
        else:
            print("❌ Failed to enable BLACS protection")
    
    except KeyboardInterrupt:
        print(f"\n⏹️ Application interrupted by user")
    except Exception as e:
        print(f"❌ Application error: {e}")
    
    finally:
        # Disable protection
        print(f"\n🔄 Disabling BLACS protection...")
        blacs.disable_protection()
        print(f"✅ Protection disabled")

if __name__ == "__main__":
    main()