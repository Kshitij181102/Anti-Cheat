#!/usr/bin/env python3
"""
BLACS Hybrid Architecture Example

Simple demonstration of BLACS hybrid anti-cheat system with both
user-level and kernel-level protection capabilities.
"""

import time
import sys
import os
from blacs.sdk.integration import BLACSIntegration, BLACSProtection
from blacs_hybrid_config import print_current_config, get_recommended_protection_mode

def simple_demo():
    """Simple demonstration of BLACS hybrid protection."""
    print("🛡️  BLACS Hybrid Anti-Cheat System Demo")
    print("=" * 50)
    
    # Show current configuration
    print_current_config()
    
    # Get recommended protection mode
    recommended = get_recommended_protection_mode()
    print(f"\n💡 Recommended mode for this system: {recommended.value}")
    
    print(f"\n🔄 Starting protection demo...")
    
    # Create BLACS integration with automatic mode selection
    blacs = BLACSIntegration("DemoApp", "1.0.0", "auto")
    
    try:
        # Enable protection
        if blacs.enable_protection():
            # Show protection status
            status = blacs.get_protection_status()
            print(f"\n📊 Protection Status:")
            print(f"   • App: {status['app_name']} (PID: {status['app_pid']})")
            print(f"   • Mode: {status['protection_mode']}")
            print(f"   • Kernel Features: {status.get('kernel_features_enabled', False)}")
            print(f"   • Detection Strength: {status.get('detection_strength', 'unknown')}")
            
            # Show system monitoring status
            system_status = status.get('system_status', {})
            if system_status:
                print(f"\n🔍 Active Monitors:")
                user_monitors = system_status.get('user_level_monitors', {})
                for monitor, info in user_monitors.items():
                    status_icon = "✅" if info.get('enabled') else "❌"
                    print(f"   {status_icon} {monitor.replace('_', ' ').title()}")
                
                kernel_monitor = system_status.get('kernel_level_monitor', {})
                if kernel_monitor and kernel_monitor.get('monitoring_active'):
                    print(f"   🔴 Kernel Monitor: Active")
                    enabled_features = kernel_monitor.get('enabled_features', [])
                    if enabled_features:
                        print(f"   🔴 Kernel Features: {', '.join(enabled_features)}")
            
            print(f"\n🔄 Simulating protected application activity...")
            print(f"💡 Try opening Cheat Engine or other cheat tools - they will be detected!")
            
            # Simulate application activity
            for i in range(10):
                print(f"   Processing frame {i+1}/10...")
                time.sleep(1)
            
            print(f"\n✅ Demo completed successfully!")
            print(f"🛡️  Your application was protected by BLACS hybrid architecture")
        
        else:
            print(f"❌ Failed to enable BLACS protection")
    
    except KeyboardInterrupt:
        print(f"\n⏹️ Demo interrupted by user")
    except Exception as e:
        print(f"❌ Demo error: {e}")
    
    finally:
        # Disable protection
        blacs.disable_protection()
        print(f"✅ Protection disabled")

def interactive_demo():
    """Interactive demo allowing user to choose protection mode."""
    print("🛡️  BLACS Interactive Demo")
    print("=" * 30)
    
    print(f"\nAvailable Protection Modes:")
    modes = [
        ("1", "user_basic", "Basic user-level protection"),
        ("2", "user_advanced", "Advanced user-level protection"),
        ("3", "hybrid_standard", "Hybrid user + kernel protection"),
        ("4", "hybrid_maximum", "Maximum hybrid protection"),
        ("5", "kernel_enterprise", "Full kernel-level protection"),
        ("6", "auto", "Automatic mode selection")
    ]
    
    for num, mode, desc in modes:
        print(f"   {num}. {mode}: {desc}")
    
    try:
        choice = input(f"\nSelect protection mode (1-6): ").strip()
        mode_map = {num: mode for num, mode, _ in modes}
        
        if choice not in mode_map:
            print(f"❌ Invalid choice. Using automatic mode.")
            protection_mode = "auto"
        else:
            protection_mode = mode_map[choice]
        
        print(f"\n🔄 Starting demo with {protection_mode} mode...")
        
        # Create integration with selected mode
        blacs = BLACSIntegration("InteractiveDemo", "1.0.0", protection_mode)
        
        if blacs.enable_protection():
            status = blacs.get_protection_status()
            print(f"\n✅ Protection enabled!")
            print(f"   • Mode: {status['protection_mode']}")
            print(f"   • Kernel Features: {status.get('kernel_features_enabled', False)}")
            
            input(f"\n⏸️  Press Enter to continue (try opening cheat tools now)...")
            
            print(f"🔄 Running protected simulation...")
            for i in range(5):
                print(f"   Activity {i+1}/5...")
                time.sleep(1)
            
            print(f"✅ Interactive demo completed!")
        
        blacs.disable_protection()
        
    except KeyboardInterrupt:
        print(f"\n⏹️ Demo interrupted")
    except Exception as e:
        print(f"❌ Error: {e}")

def context_manager_demo():
    """Demonstrate context manager usage."""
    print("🎯 Context Manager Demo")
    print("=" * 25)
    
    print(f"🔄 Using context manager for automatic protection...")
    
    try:
        with BLACSProtection("ContextDemo", "user_advanced") as blacs:
            print(f"✅ Protection automatically enabled")
            
            status = blacs.get_protection_status()
            print(f"   • Mode: {status['protection_mode']}")
            print(f"   • Kernel Features: {status.get('kernel_features_enabled', False)}")
            
            # Simulate work
            for i in range(3):
                print(f"   • Doing protected work... {i+1}/3")
                time.sleep(0.5)
        
        print(f"✅ Protection automatically disabled")
        
    except Exception as e:
        print(f"❌ Context manager demo error: {e}")

def main():
    """Main function with demo options."""
    print("🚀 BLACS Hybrid Architecture Demonstration")
    print("=" * 45)
    
    print(f"\nDemo Options:")
    print(f"   1. Simple Demo (automatic mode)")
    print(f"   2. Interactive Demo (choose mode)")
    print(f"   3. Context Manager Demo")
    print(f"   4. All Demos")
    
    try:
        choice = input(f"\nSelect demo (1-4): ").strip()
        
        if choice == "1":
            simple_demo()
        elif choice == "2":
            interactive_demo()
        elif choice == "3":
            context_manager_demo()
        elif choice == "4":
            print(f"\n🔄 Running all demos...\n")
            simple_demo()
            print(f"\n" + "="*50 + "\n")
            interactive_demo()
            print(f"\n" + "="*50 + "\n")
            context_manager_demo()
        else:
            print(f"❌ Invalid choice. Running simple demo...")
            simple_demo()
        
        print(f"\n" + "="*50)
        print(f"✅ BLACS DEMO COMPLETED")
        print(f"=" * 50)
        
        print(f"\n💡 Key Features Demonstrated:")
        print(f"   • Hybrid user-level + kernel-level protection")
        print(f"   • Automatic system capability detection")
        print(f"   • Multiple protection modes")
        print(f"   • Easy integration methods")
        print(f"   • Real-time threat detection")
        
        print(f"\n🔒 Next Steps:")
        print(f"   • Try running 'python hybrid_example.py' for comprehensive demo")
        print(f"   • Read HYBRID_ARCHITECTURE_GUIDE.md for detailed setup")
        print(f"   • Integrate BLACS into your own applications")
        
    except KeyboardInterrupt:
        print(f"\n⏹️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()