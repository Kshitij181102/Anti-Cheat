#!/usr/bin/env python3
"""
Test BLACS Hybrid Architecture

Quick test to verify the hybrid architecture is working correctly.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all hybrid architecture components can be imported."""
    print("🔧 Testing BLACS Hybrid Architecture Imports...")
    
    try:
        # Test hybrid configuration
        from blacs_hybrid_config import (
            ProtectionMode, print_current_config, get_recommended_protection_mode,
            validate_configuration, set_protection_mode
        )
        print("✅ Hybrid configuration imported successfully")
        
        # Test kernel components
        from blacs.kernel.kernel_interface import KernelInterface
        from blacs.kernel.kernel_monitor import KernelMonitor
        from blacs.kernel.driver_manager import DriverManager
        print("✅ Kernel components imported successfully")
        
        # Test updated BLACS system
        from blacs.blacs_system import BLACSSystem
        print("✅ BLACS system imported successfully")
        
        # Test updated SDK
        from blacs.sdk.integration import BLACSIntegration, BLACSProtection, blacs_protected
        print("✅ SDK integration imported successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_configuration():
    """Test hybrid configuration system."""
    print("\n🔧 Testing Hybrid Configuration...")
    
    try:
        from blacs_hybrid_config import (
            ProtectionMode, get_current_config, validate_configuration,
            get_recommended_protection_mode
        )
        
        # Test configuration access
        config = get_current_config()
        print(f"✅ Current config loaded: {config.get('description', 'Unknown')}")
        
        # Test validation
        is_valid, errors = validate_configuration()
        if is_valid:
            print("✅ Configuration is valid")
        else:
            print(f"⚠️ Configuration issues: {len(errors)} errors")
            for error in errors:
                print(f"   • {error}")
        
        # Test recommended mode
        recommended = get_recommended_protection_mode()
        print(f"✅ Recommended mode: {recommended.value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test error: {e}")
        return False

def test_kernel_interface():
    """Test kernel interface components."""
    print("\n🔧 Testing Kernel Interface...")
    
    try:
        from blacs.kernel.kernel_interface import KernelInterface
        
        # Create kernel interface
        kernel = KernelInterface()
        print("✅ Kernel interface created")
        
        # Test admin check
        has_admin = kernel.check_admin_privileges()
        print(f"✅ Admin privileges: {has_admin}")
        
        # Test module status
        status = kernel.get_kernel_module_status()
        print(f"✅ Kernel module status: {status.value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Kernel interface test error: {e}")
        return False

def test_blacs_system():
    """Test BLACS system with hybrid architecture."""
    print("\n🔧 Testing BLACS System...")
    
    try:
        from blacs.blacs_system import BLACSSystem
        from blacs_hybrid_config import ProtectionMode
        
        # Create system with user-level protection
        blacs = BLACSSystem.create_default_system(ProtectionMode.USER_ADVANCED)
        print("✅ BLACS system created with user-level protection")
        
        # Test system status
        status = blacs.get_system_status()
        print(f"✅ System status: {status['protection_mode']}")
        print(f"   • Kernel features: {status['kernel_features_enabled']}")
        print(f"   • User monitors: {len(status['user_level_monitors'])}")
        
        # Test available modes
        modes = blacs.get_available_protection_modes()
        print(f"✅ Available modes: {', '.join(modes)}")
        
        return True
        
    except Exception as e:
        print(f"❌ BLACS system test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_sdk_integration():
    """Test SDK integration with hybrid architecture."""
    print("\n🔧 Testing SDK Integration...")
    
    try:
        from blacs.sdk.integration import BLACSIntegration
        
        # Create integration with automatic mode
        blacs = BLACSIntegration("TestApp", "1.0.0", "auto")
        print("✅ BLACS integration created")
        
        # Test available modes
        modes = blacs.get_available_protection_modes()
        print(f"✅ Available protection modes: {', '.join(modes)}")
        
        # Test protection status (without enabling)
        status = blacs.get_protection_status()
        print(f"✅ Protection status: {status['protection_mode']}")
        print(f"   • Protected: {status['is_protected']}")
        
        return True
        
    except Exception as e:
        print(f"❌ SDK integration test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all hybrid architecture tests."""
    print("🚀 BLACS Hybrid Architecture Test Suite")
    print("=" * 45)
    
    tests = [
        ("Import Test", test_imports),
        ("Configuration Test", test_configuration),
        ("Kernel Interface Test", test_kernel_interface),
        ("BLACS System Test", test_blacs_system),
        ("SDK Integration Test", test_sdk_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {e}")
    
    print(f"\n" + "="*60)
    print(f"🏆 TEST RESULTS: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("✅ All tests passed! BLACS Hybrid Architecture is working correctly.")
        print("\n🔒 Next Steps:")
        print("   • Run 'python example.py' for interactive demo")
        print("   • Run 'python hybrid_example.py' for comprehensive demo")
        print("   • Read HYBRID_ARCHITECTURE_GUIDE.md for detailed setup")
    else:
        print(f"❌ {total - passed} tests failed. Please check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)