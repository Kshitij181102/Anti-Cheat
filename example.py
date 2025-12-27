#!/usr/bin/env python3
"""
BLACS Example - Simplified

Simple demonstration of BLACS anti-cheat system.
"""

import time
import sys
import os
from blacs.sdk.integration import BLACSIntegration

def main():
    """Main example function."""
    print("🛡️  BLACS Anti-Cheat System Demo")
    print("=" * 40)
    
    # Create BLACS integration
    blacs = BLACSIntegration("ExampleApp", "1.0.0")
    
    try:
        # Enable protection
        print("🔄 Enabling BLACS protection...")
        if blacs.enable_protection("high"):
            print("✅ BLACS protection enabled successfully!")
            
            # Show protection status
            status = blacs.get_protection_status()
            print(f"\n📊 Protection Status:")
            print(f"   • App: {status['app_name']}")
            print(f"   • Version: {status['app_version']}")
            print(f"   • PID: {status['app_pid']}")
            print(f"   • Protected: {status['is_protected']}")
            print(f"   • Level: {status['protection_level']}")
            
            # Show system status
            system_status = status.get('system_status')
            if system_status:
                print(f"\n🔍 System Monitoring:")
                monitors = system_status.get('monitors', {})
                for monitor, info in monitors.items():
                    status_icon = "✅" if info.get('enabled') else "❌"
                    violations = info.get('violations_count', 0)
                    print(f"   {status_icon} {monitor.replace('_', ' ').title()}: {violations} violations")
            
            print(f"\n💡 Try opening Cheat Engine or other cheat tools - they will be detected!")
            print(f"🔄 Simulating protected application activity...")
            
            # Simulate application activity
            for i in range(10):
                print(f"   Processing frame {i+1}/10...")
                time.sleep(1)
            
            print(f"\n✅ Application completed successfully!")
            print(f"🛡️  Your application was protected by BLACS")
        
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