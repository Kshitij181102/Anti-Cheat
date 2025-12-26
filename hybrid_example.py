#!/usr/bin/env python3
"""
BLACS Hybrid Architecture Example

Demonstrates the hybrid user-level + kernel-level protection capabilities
of the BLACS anti-cheat system.
"""

import time
import sys
import os
from blacs.sdk.integration import BLACSIntegration, BLACSProtection, blacs_protected
from blacs_hybrid_config import (
    ProtectionMode, print_current_config, set_protection_mode, 
    get_recommended_protection_mode, validate_configuration
)

def demonstrate_protection_modes():
    """Demonstrate different protection modes."""
    print("🛡️  BLACS Hybrid Architecture Demo")
    print("=" * 50)
    
    # Show current configuration
    print_current_config()
    
    # Validate configuration
    is_valid, errors = validate_configuration()
    if not is_valid:
        print(f"\n❌ Configuration Issues:")
        for error in errors:
            print(f"   • {error}")
        print("\n💡 Continuing with user-level protection only...")
    
    print(f"\n🔍 Available Protection Modes:")
    modes = [
        ("user_basic", "Basic user-level protection"),
        ("user_advanced", "Advanced user-level protection"),
        ("hybrid_standard", "Hybrid user + kernel protection"),
        ("hybrid_maximum", "Maximum hybrid protection"),
        ("kernel_enterprise", "Full kernel-level enterprise protection")
    ]
    
    for mode, description in modes:
        print(f"   • {mode}: {description}")
    
    # Get recommended mode
    recommended = get_recommended_protection_mode()
    print(f"\n💡 Recommended mode for this system: {recommended.value}")

def demo_user_level_protection():
    """Demonstrate user-level protection."""
    print(f"\n" + "="*60)
    print("🔵 USER-LEVEL PROTECTION DEMO")
    print("="*60)
    
    # Create integration with user-level protection
    blacs = BLACSIntegration("HybridDemo", "1.0.0", "user_advanced")
    
    try:
        # Enable protection
        if blacs.enable_protection():
            print(f"\n📊 Protection Status:")
            status = blacs.get_protection_status()
            print(f"   • App: {status['app_name']} (PID: {status['app_pid']})")
            print(f"   • Mode: {status['protection_mode']}")
            print(f"   • Kernel Features: {status.get('kernel_features_enabled', False)}")
            print(f"   • Detection Strength: {status.get('detection_strength', 'unknown')}")
            
            # Simulate some activity
            print(f"\n🔄 Simulating protected application activity...")
            for i in range(5):
                print(f"   Processing frame {i+1}/5...")
                time.sleep(1)
            
            print(f"✅ User-level protection demo completed successfully")
        
    except Exception as e:
        print(f"❌ User-level demo error: {e}")
    
    finally:
        blacs.disable_protection()

def demo_hybrid_protection():
    """Demonstrate hybrid user + kernel protection."""
    print(f"\n" + "="*60)
    print("🔴 HYBRID PROTECTION DEMO")
    print("="*60)
    
    # Create integration with hybrid protection
    blacs = BLACSIntegration("HybridDemo", "1.0.0", "hybrid_standard")
    
    try:
        # Enable protection
        if blacs.enable_protection():
            print(f"\n📊 Protection Status:")
            status = blacs.get_protection_status()
            print(f"   • App: {status['app_name']} (PID: {status['app_pid']})")
            print(f"   • Mode: {status['protection_mode']}")
            print(f"   • Kernel Features: {status.get('kernel_features_enabled', False)}")
            print(f"   • Detection Strength: {status.get('detection_strength', 'unknown')}")
            
            # Show system status
            system_status = status.get('system_status', {})
            if system_status:
                print(f"\n🔍 System Monitoring Status:")
                user_monitors = system_status.get('user_level_monitors', {})
                for monitor, info in user_monitors.items():
                    status_icon = "✅" if info.get('enabled') else "❌"
                    print(f"   {status_icon} {monitor.replace('_', ' ').title()}")
                
                kernel_monitor = system_status.get('kernel_level_monitor', {})
                if kernel_monitor:
                    print(f"   🔴 Kernel Monitor: {kernel_monitor.get('monitoring_active', False)}")
                    enabled_features = kernel_monitor.get('enabled_features', [])
                    if enabled_features:
                        print(f"   🔴 Kernel Features: {', '.join(enabled_features)}")
            
            # Simulate some activity
            print(f"\n🔄 Simulating protected application activity...")
            for i in range(5):
                print(f"   Processing frame {i+1}/5...")
                time.sleep(1)
            
            print(f"✅ Hybrid protection demo completed successfully")
        
    except Exception as e:
        print(f"❌ Hybrid demo error: {e}")
    
    finally:
        blacs.disable_protection()

@blacs_protected("DecoratorDemo", "user_advanced")
def protected_function():
    """Example of using the decorator for automatic protection."""
    print(f"\n🎯 This function is automatically protected by BLACS!")
    print(f"   • Protection is enabled when function starts")
    print(f"   • Protection is disabled when function ends")
    
    for i in range(3):
        print(f"   • Doing protected work... {i+1}/3")
        time.sleep(0.5)
    
    return "Protected function completed successfully"

def demo_context_manager():
    """Demonstrate context manager usage."""
    print(f"\n" + "="*60)
    print("🎯 CONTEXT MANAGER DEMO")
    print("="*60)
    
    print(f"🔄 Using context manager for temporary protection...")
    
    with BLACSProtection("ContextDemo", "user_advanced") as blacs:
        print(f"✅ Protection automatically enabled")
        
        status = blacs.get_protection_status()
        print(f"   • Mode: {status['protection_mode']}")
        print(f"   • Kernel Features: {status.get('kernel_features_enabled', False)}")
        
        # Do some work
        for i in range(3):
            print(f"   • Doing protected work... {i+1}/3")
            time.sleep(0.5)
    
    print(f"✅ Protection automatically disabled")

def demo_mode_switching():
    """Demonstrate switching between protection modes."""
    print(f"\n" + "="*60)
    print("🔄 PROTECTION MODE SWITCHING DEMO")
    print("="*60)
    
    blacs = BLACSIntegration("SwitchDemo", "1.0.0", "user_basic")
    
    try:
        if blacs.enable_protection():
            print(f"✅ Started with: {blacs.protection_mode.value}")
            
            # Show available modes
            available_modes = blacs.get_available_protection_modes()
            print(f"\n📋 Available modes: {', '.join(available_modes)}")
            
            # Try switching modes (note: switching requires stopping monitoring first)
            print(f"\n🔄 Note: Mode switching requires restarting protection")
            print(f"   This is a limitation of the current implementation")
            
            # Demonstrate getting status
            status = blacs.get_protection_status()
            print(f"\n📊 Current Status:")
            print(f"   • Mode: {status['protection_mode']}")
            print(f"   • Active: {status['is_protected']}")
    
    except Exception as e:
        print(f"❌ Mode switching demo error: {e}")
    
    finally:
        blacs.disable_protection()

def main():
    """Main demonstration function."""
    print("🚀 Starting BLACS Hybrid Architecture Demonstration")
    print("=" * 60)
    
    try:
        # Show protection modes and configuration
        demonstrate_protection_modes()
        
        # Demo user-level protection
        demo_user_level_protection()
        
        # Demo hybrid protection (will fall back to user-level if kernel not available)
        demo_hybrid_protection()
        
        # Demo decorator usage
        print(f"\n" + "="*60)
        print("🎯 DECORATOR DEMO")
        print("="*60)
        result = protected_function()
        print(f"✅ {result}")
        
        # Demo context manager
        demo_context_manager()
        
        # Demo mode switching
        demo_mode_switching()
        
        print(f"\n" + "="*60)
        print("✅ BLACS HYBRID DEMO COMPLETED SUCCESSFULLY")
        print("="*60)
        
        print(f"\n💡 Key Features Demonstrated:")
        print(f"   • Multiple protection modes (user-level to kernel-level)")
        print(f"   • Automatic system capability detection")
        print(f"   • Fallback to user-level when kernel unavailable")
        print(f"   • Easy integration with decorator and context manager")
        print(f"   • Real-time protection status monitoring")
        print(f"   • Comprehensive threat detection and prevention")
        
        print(f"\n🔒 Security Benefits:")
        print(f"   • Tamper-resistant kernel-level protection")
        print(f"   • Multi-layered defense against cheating tools")
        print(f"   • Real-time memory and process monitoring")
        print(f"   • Advanced behavioral analysis")
        print(f"   • Automatic threat termination")
        
    except KeyboardInterrupt:
        print(f"\n⏹️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()