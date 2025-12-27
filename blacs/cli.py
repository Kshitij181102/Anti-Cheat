#!/usr/bin/env python3
"""
BLACS Command Line Interface with DSLL Technology

Simple CLI for protecting applications with BLACS anti-cheat system.
"""

import sys
import os
import time
import argparse
import subprocess
from typing import Optional

from .sdk.integration import BLACSIntegration


class BLACSCLI:
    """BLACS Command Line Interface."""
    
    def __init__(self):
        self.blacs: Optional[BLACSIntegration] = None
        self.protected_process: Optional[subprocess.Popen] = None
    
    def protect_application(self, executable_path: str, protection_level: str = "high") -> bool:
        """Protect an application with BLACS."""
        if not os.path.exists(executable_path):
            print(f"❌ Error: Executable not found: {executable_path}")
            return False
        
        app_name = os.path.basename(executable_path)
        print(f"🛡️ Starting BLACS protection for {app_name}")
        print(f"📁 Executable: {executable_path}")
        print(f"🔒 Protection Level: {protection_level.upper()}")
        print(f"🔍 DSLL Technology: ENABLED")
        
        try:
            # Initialize BLACS
            self.blacs = BLACSIntegration(app_name, "1.0.0")
            
            # Enable protection
            if not self.blacs.enable_protection(protection_level):
                print("❌ Failed to enable BLACS protection")
                return False
            
            # Launch the protected application
            print(f"🚀 Launching protected application...")
            self.protected_process = subprocess.Popen([executable_path])
            
            # Add the process to DSLL protection
            if self.blacs.blacs_system and self.blacs.blacs_system.dsll_monitor:
                self.blacs.blacs_system.dsll_monitor.add_protected_process(self.protected_process.pid)
            
            print(f"✅ Application launched with BLACS protection")
            print(f"🔍 Process ID: {self.protected_process.pid}")
            print(f"🛡️ DSLL monitoring active")
            print(f"\n💡 Press Ctrl+C to stop protection and close application")
            
            # Monitor the application
            self._monitor_application()
            
            return True
            
        except Exception as e:
            print(f"❌ Error protecting application: {e}")
            return False
    
    def _monitor_application(self):
        """Monitor the protected application."""
        try:
            while True:
                # Check if process is still running
                if self.protected_process.poll() is not None:
                    print(f"\n✅ Protected application has exited")
                    break
                
                # Show periodic status updates
                if self.blacs:
                    status = self.blacs.get_protection_status()
                    dsll_stats = self.blacs.get_dsll_statistics()
                    
                    if "error" not in dsll_stats:
                        syscalls = dsll_stats.get('total_syscalls_recorded', 0)
                        patterns = dsll_stats.get('suspicious_patterns_detected', 0)
                        
                        if syscalls > 0 or patterns > 0:
                            print(f"🔍 DSLL Update: {syscalls} syscalls, {patterns} patterns detected")
                
                time.sleep(5)  # Update every 5 seconds
                
        except KeyboardInterrupt:
            print(f"\n⏹️ Stopping protection...")
            self._cleanup()
    
    def _cleanup(self):
        """Clean up resources."""
        try:
            # Terminate protected process
            if self.protected_process and self.protected_process.poll() is None:
                print(f"🔄 Terminating protected application...")
                self.protected_process.terminate()
                
                # Wait for graceful shutdown
                try:
                    self.protected_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"⚠️ Force killing application...")
                    self.protected_process.kill()
            
            # Disable BLACS protection
            if self.blacs:
                print(f"🔄 Disabling BLACS protection...")
                self.blacs.disable_protection()
            
            print(f"✅ Cleanup completed")
            
        except Exception as e:
            print(f"❌ Cleanup error: {e}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="BLACS Anti-Cheat System with DSLL Technology",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m blacs.cli protect notepad.exe
  python -m blacs.cli protect "C:\\Windows\\System32\\calc.exe" --level high
  python -m blacs.cli protect "C:\\Program Files\\MyGame\\game.exe" --level maximum

Protection Levels:
  low      - Basic protection, DSLL disabled
  medium   - Balanced detection, DSLL enabled (recommended)
  high     - Strict detection, Full DSLL monitoring (default)
  maximum  - Extreme sensitivity, Advanced DSLL analysis
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Protect command
    protect_parser = subparsers.add_parser('protect', help='Protect an application')
    protect_parser.add_argument('executable', help='Path to executable to protect')
    protect_parser.add_argument('--level', '-l', default='high', 
                               choices=['low', 'medium', 'high', 'maximum'],
                               help='Protection level (default: high)')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = BLACSCLI()
    
    if args.command == 'protect':
        print("🛡️ BLACS Anti-Cheat System with DSLL Technology")
        print("=" * 55)
        
        success = cli.protect_application(args.executable, args.level)
        
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    main()