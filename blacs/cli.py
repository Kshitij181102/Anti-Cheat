#!/usr/bin/env python3
"""
BLACS Command Line Interface - Tamper-Proof Guardian

CLI interface for the BLACS Guardian tamper-proof protection system.
Requires Administrator privileges for tamper-resistant operation.
"""

import sys
import os
import subprocess

def main():
    """Main CLI function - redirects to BLACS Guardian."""
    print("🛡️ BLACS Guardian - Tamper-Proof Protection System")
    print("=" * 50)
    print("🔍 Revolutionary DSLL Technology")
    print("⚠️  Requires Administrator privileges")
    print()
    
    if len(sys.argv) < 3 or sys.argv[1] != 'protect':
        print("Usage: python -m blacs.cli protect <app_path> [--level <level>]")
        print()
        print("Examples:")
        print("  python -m blacs.cli protect calc.exe --level safe")
        print("  python -m blacs.cli protect calc.exe --level high")
        print("  python -m blacs.cli protect \"C:\\Program Files\\MyGame\\game.exe\" --level maximum")
        print()
        print("Protection levels: safe, low, medium, high, maximum")
        print()
        print("Note: This CLI redirects to the BLACS Guardian system.")
        print("      For direct access, use: python blacs_guardian.py <app_path>")
        return
    
    # Extract arguments
    app_path = sys.argv[2]
    level = "high"
    
    # Parse level argument
    if len(sys.argv) > 3 and sys.argv[3] == '--level' and len(sys.argv) > 4:
        level = sys.argv[4]
    
    print(f"🎯 Target: {app_path}")
    print(f"🔒 Protection Level: {level.upper()}")
    print(f"🛡️ Redirecting to BLACS Guardian...")
    print()
    
    # Redirect to guardian
    try:
        guardian_cmd = [sys.executable, "blacs_guardian.py", app_path, "--level", level]
        subprocess.run(guardian_cmd)
    except Exception as e:
        print(f"❌ Failed to start BLACS Guardian: {e}")
        print("Make sure blacs_guardian.py is in the current directory")
        sys.exit(1)

if __name__ == "__main__":
    main()