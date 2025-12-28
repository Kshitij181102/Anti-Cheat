#!/usr/bin/env python3
"""
BLACS Quick Launcher

Super simple launcher for protecting applications with BLACS.
Just run: python blacs_protect.py
"""

import os
import sys

def main():
    """Interactive launcher for BLACS protection."""
    print("🛡️ BLACS Universal Application Protector")
    print("=" * 45)
    print("🔍 Revolutionary DSLL Technology")
    print()
    
    # Get application path from user
    print("📁 Enter the application you want to protect:")
    print("   Examples:")
    print("   • calc.exe")
    print("   • notepad.exe")
    print("   • C:\\Program Files\\MyGame\\game.exe")
    print()
    
    app_path = input("🎯 Application path: ").strip()
    if not app_path:
        print("❌ No application specified")
        return
    
    # Get protection level
    print("\n🔒 Choose protection level:")
    print("   1. Low      - Basic protection")
    print("   2. Medium   - Balanced detection (recommended)")
    print("   3. High     - Strict detection (default)")
    print("   4. Maximum  - Extreme sensitivity")
    print()
    
    level_choice = input("🔒 Protection level (1-4, default=3): ").strip()
    
    level_map = {
        "1": "low",
        "2": "medium", 
        "3": "high",
        "4": "maximum"
    }
    
    protection_level = level_map.get(level_choice, "high")
    
    print(f"\n🚀 Starting BLACS protection...")
    print(f"🎯 Target: {app_path}")
    print(f"🔒 Level: {protection_level.upper()}")
    print(f"🔍 DSLL: ENABLED")
    print()
    
    # Launch the protector
    try:
        import subprocess
        cmd = [sys.executable, "protect_app.py", app_path, "--level", protection_level]
        subprocess.run(cmd)
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nTry running: python protect_app.py \"your_app_path\"")

if __name__ == "__main__":
    main()