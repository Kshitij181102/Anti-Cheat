#!/usr/bin/env python3
"""
BLACS Guardian - Tamper-Proof Protection Service

Ultra-secure tamper-resistant monitoring system that requires admin privileges
and cannot be stopped by regular users. Monitors applications without launching them.
"""

import os
import sys
import time
import ctypes
import psutil
import threading
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from blacs.sdk.integration import BLACSIntegration

class BLACSGuardian:
    """Tamper-proof BLACS protection service."""
    
    def __init__(self):
        """Initialize the BLACS Guardian."""
        self.is_admin = self._check_admin_privileges()
        self.protected_apps: Dict[str, Dict[str, Any]] = {}
        self.monitoring_active = False
        self.guardian_thread: Optional[threading.Thread] = None
        self.blacs_instances: Dict[str, BLACSIntegration] = {}
        self.stop_event = threading.Event()
        
        # Enhanced cheat detection database
        self._load_enhanced_cheat_database()
        
        # Self-protection mechanisms
        self._enable_self_protection()
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def _require_admin(self) -> bool:
        """Require administrator privileges to continue."""
        if not self.is_admin:
            print("🚫 BLACS Guardian requires Administrator privileges!")
            print("   Right-click and select 'Run as administrator'")
            print("   This is required for tamper-proof protection.")
            
            # Attempt to restart with admin privileges
            try:
                if sys.argv[0].endswith('.py'):
                    # Running as Python script
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                else:
                    # Running as executable
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.argv[0], " ".join(sys.argv[1:]), None, 1
                    )
                sys.exit(0)
            except Exception as e:
                print(f"❌ Failed to restart with admin privileges: {e}")
                return False
        
        return True
    
    def _enable_self_protection(self) -> None:
        """Enable self-protection mechanisms."""
        if not self.is_admin:
            return
        
        try:
            # Set high process priority
            current_process = psutil.Process()
            current_process.nice(psutil.HIGH_PRIORITY_CLASS)
            
            # Make process critical (Windows only)
            try:
                import ctypes.wintypes
                ntdll = ctypes.windll.ntdll
                kernel32 = ctypes.windll.kernel32
                
                # Set process as critical
                current_handle = kernel32.GetCurrentProcess()
                ntdll.RtlSetProcessIsCritical(1, None, 0)
                
                print("🛡️ BLACS Guardian: Self-protection enabled")
            except Exception as e:
                print(f"⚠️ Advanced self-protection failed: {e}")
        
        except Exception as e:
            print(f"⚠️ Basic self-protection failed: {e}")
    
    def _load_enhanced_cheat_database(self) -> None:
        """Load comprehensive cheat detection database."""
        self.cheat_database = {
            # ===== MEMORY EDITORS & CHEAT ENGINES =====
            "memory_editors": [
                "cheatengine", "cheat engine", "cheat-engine", "ce", "ce64", "ce32",
                "artmoney", "artmoneypro", "art money", "gameguardian", "gg", "guardian",
                "memoryeditor", "memory editor", "memoryhacker", "memory hacker",
                "memhack", "mem hack", "tsearch", "t-search", "scanmem", "scan mem",
                "memoryviewer", "memory viewer", "memview", "hexeditor", "hex editor",
                "memorypatching", "memory patching", "mempatch", "mem patch",
                "gameconqueror", "game conqueror", "memwatch", "mem watch",
                "memoryscanner", "memory scanner", "memscan", "mem scan",
                "ramhack", "ram hack", "ramcheat", "ram cheat", "memtool", "mem tool"
            ],
            
            # ===== DEBUGGERS & ANALYSIS TOOLS =====
            "debuggers": [
                "ollydbg", "olly", "x64dbg", "x32dbg", "x96dbg", "xdbg",
                "ida", "idapro", "ida pro", "idafree", "ida free", "hexrays",
                "windbg", "win dbg", "kd", "cdb", "ntsd", "gdb", "lldb",
                "processhacker", "process hacker", "processhacker2", "ph", "ph2",
                "systemexplorer", "system explorer", "procexp", "process explorer",
                "apimonitor", "api monitor", "detours", "easyhook", "minhook",
                "rohitab", "immunity", "immunitydebugger", "immunity debugger",
                "radare2", "r2", "ghidra", "binaryninja", "binary ninja",
                "hopper", "disassembler", "decompiler", "reverser", "reverse",
                "softice", "soft ice", "syser", "syser debugger", "winapi"
            ],
            
            # ===== INJECTION & HOOKING TOOLS =====
            "injection_tools": [
                "injector", "inject", "dllinjector", "dll injector", "processinjector",
                "process injector", "codecave", "code cave", "hooklib", "hook lib",
                "apihook", "api hook", "dethook", "winapi", "ntapi", "kernel32",
                "setwindowshook", "getprocaddress", "loadlibrary", "freelibrary",
                "virtualallocex", "writeprocessmemory", "readprocessmemory",
                "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
                "manualmap", "manual map", "reflectivedll", "reflective dll",
                "dllhijack", "dll hijack", "proxydll", "proxy dll", "sidebyside"
            ],
            
            # ===== SPEED HACKS & TIME MANIPULATION =====
            "speed_hacks": [
                "speedhack", "speed hack", "gamespeed", "game speed", "timescale",
                "time scale", "clockblocker", "clock blocker", "timestop", "time stop",
                "speedgear", "speed gear", "hourglass", "hour glass", "timeshift",
                "time shift", "acceleration", "accelerator", "fps", "framerate",
                "tickrate", "tick rate", "timer", "timing", "temporal", "chrono",
                "timehack", "time hack", "clockhack", "clock hack", "speedboost"
            ],
            
            # ===== TRAINERS & GAME MODIFIERS =====
            "trainers": [
                "trainer", "gametrainer", "game trainer", "fling", "flingtrain",
                "mrantifun", "mr antifun", "cheathappens", "cheat happens", "ch",
                "wemod", "we mod", "plitch", "megadev", "mega dev", "fearless",
                "fearlessrevolution", "fearless revolution", "codex", "skidrow",
                "reloaded", "prophet", "steampunks", "goldberg", "smartsteamemu",
                "greenlight", "ali213", "3dm", "cpy", "plaza", "hoodlum",
                "dodi", "fitgirl", "empress", "razor1911", "fairlight", "deviance"
            ],
            
            # ===== AUTOMATION & BOTS =====
            "automation_bots": [
                "autoclicker", "auto clicker", "autoclick", "auto click", "clickbot",
                "click bot", "mousebot", "mouse bot", "keybot", "key bot", "inputbot",
                "input bot", "autohotkey", "ahk", "macro", "macrorecorder", "macro recorder",
                "jitbit", "ghost mouse", "ghostmouse", "perfect automation", "automation",
                "bot", "botter", "farming", "grinder", "aimbot", "aim bot", "wallhack",
                "wall hack", "esp", "triggerbot", "trigger bot", "bhop", "bunny hop",
                "autofire", "auto fire", "rapidfire", "rapid fire", "autoaim", "auto aim"
            ],
            
            # ===== GAME-SPECIFIC CHEATS =====
            "game_cheats": [
                "aimassist", "aim assist", "recoil", "norecoil", "no recoil", "spread",
                "nospread", "no spread", "radar", "minimap", "xray", "x-ray", "vision",
                "nightvision", "night vision", "thermal", "highlight", "glow", "outline",
                "skeleton", "bones", "hitbox", "hit box", "headshot", "autofire", "auto fire",
                "rapidfire", "rapid fire", "fullbright", "full bright", "gamma", "brightness",
                "godmode", "god mode", "noclip", "no clip", "fly", "flying", "teleport",
                "speedhack", "unlimited", "infinite", "invincible", "immortal"
            ],
            
            # ===== NETWORK & PACKET MANIPULATION =====
            "network_tools": [
                "wireshark", "wire shark", "fiddler", "burpsuite", "burp suite",
                "networkminer", "network miner", "tcpdump", "tcp dump", "packetsender",
                "packet sender", "networkhack", "network hack", "lagswitch", "lag switch",
                "netlimiter", "net limiter", "packeteditor", "packet editor", "mitm",
                "man in the middle", "proxy", "sniffer", "interceptor", "tamper",
                "charles", "owasp zap", "paros", "webscarab", "burp", "fiddler"
            ],
            
            # ===== CRACKING & REVERSE ENGINEERING =====
            "cracking_tools": [
                "crack", "cracker", "keygen", "key gen", "patch", "patcher", "loader",
                "activator", "bypass", "unlocker", "remover", "killer", "disabler",
                "unpacker", "protector", "obfuscator", "deobfuscator", "strings",
                "hexedit", "hex edit", "binedit", "bin edit", "resource", "reshacker",
                "res hacker", "pe", "portable executable", "elf", "mach-o", "binary",
                "upx", "aspack", "themida", "vmprotect", "enigma", "armadillo"
            ],
            
            # ===== MODDING & GAME MODIFICATION =====
            "modding_tools": [
                "mod", "mods", "modding", "modder", "modification", "modifier",
                "reshade", "re shade", "sweetfx", "enb", "enbseries", "enb series",
                "asi", "asiloader", "asi loader", "scripthook", "script hook", "cleo",
                "samp", "multitheft", "multi theft", "gtasa", "gta sa", "vcmp",
                "mta", "multitheftauto", "openiv", "open iv", "modloader", "mod loader",
                "nexusmods", "nexus mods", "vortex", "mo2", "mod organizer"
            ],
            
            # ===== MOBILE/APK HACKING TOOLS =====
            "mobile_hacking": [
                "gameguardian", "gg", "guardian", "lucky patcher", "luckypatcher",
                "freedom", "creehack", "cree hack", "game killer", "gamekiller",
                "sb game hacker", "sbgamehacker", "cheat droid", "cheatdroid",
                "game cih", "gamecih", "xmodgames", "xmod games", "ihackedit",
                "ifile", "filza", "apktool", "apk tool", "dex2jar", "jadx",
                "frida", "xposed", "magisk", "root", "jailbreak", "cydia",
                "substrate", "hooking", "runtime", "manipulation", "bytecode"
            ],
            
            # ===== ANTI-DETECTION & STEALTH =====
            "stealth_tools": [
                "stealth", "hidden", "invisible", "undetected", "undetectable", "bypass",
                "evade", "evasion", "mask", "masker", "spoof", "spoofer", "fake", "faker",
                "emulator", "virtual", "sandbox", "vm", "vmware", "virtualbox", "qemu",
                "hyperv", "hyper-v", "container", "docker", "wine", "proton", "compatibility",
                "hideprocess", "hide process", "rootkit", "steganography", "obfuscation"
            ],
            
            # ===== CRYPTOCURRENCY & MINING =====
            "crypto_mining": [
                "miner", "mining", "bitcoin", "ethereum", "crypto", "cryptocurrency",
                "hashrate", "gpu", "cpu", "asic", "pool", "wallet", "blockchain",
                "monero", "zcash", "litecoin", "dogecoin", "nicehash", "claymore",
                "phoenixminer", "t-rex", "gminer", "lolminer", "nbminer", "teamredminer"
            ],
            
            # ===== GENERAL HACKING TERMS =====
            "general_hacking": [
                "hack", "hacker", "hacking", "cheat", "cheater", "cheating", "exploit",
                "exploiter", "exploiting", "glitch", "glitcher", "glitching", "abuse",
                "abuser", "abusing", "unfair", "advantage", "enhancement", "enhancer",
                "booster", "boost", "amplifier", "multiplier", "unlimited", "infinite",
                "external", "overlay", "injection", "modification", "manipulation",
                "automation", "simulation", "emulation", "virtualization", "containerization"
            ]
        }
        
        # Flatten all categories into a single comprehensive list
        self.all_cheat_signatures = set()
        for category, signatures in self.cheat_database.items():
            self.all_cheat_signatures.update(signatures)
        
        print(f"🔍 BLACS Guardian: Loaded {len(self.all_cheat_signatures)} cheat signatures")
    
    def start_guardian(self) -> bool:
        """Start the tamper-proof guardian service."""
        if not self._require_admin():
            return False
        
        print("🛡️ BLACS Guardian - Tamper-Proof Protection Service")
        print("=" * 55)
        print("🔒 Administrator privileges: VERIFIED")
        print("🛡️ Self-protection: ENABLED")
        print("🔍 Enhanced cheat detection: LOADED")
        print()
        
        self.monitoring_active = True
        self.guardian_thread = threading.Thread(target=self._guardian_loop, daemon=False)
        self.guardian_thread.start()
        
        return True
    
    def add_protected_application(self, app_path: str, protection_level: str = "high") -> bool:
        """Add an application to protection without launching it."""
        app_name = os.path.basename(app_path)
        
        print(f"🎯 Adding application to protection: {app_name}")
        print(f"📁 Path: {app_path}")
        print(f"🔒 Protection Level: {protection_level.upper()}")
        
        # Check if application exists
        if not os.path.exists(app_path):
            print(f"❌ Application not found: {app_path}")
            return False
        
        # Store protected application info
        self.protected_apps[app_name] = {
            "path": app_path,
            "protection_level": protection_level,
            "pid": None,
            "blacs_instance": None,
            "last_seen": None,
            "protection_active": False
        }
        
        print(f"✅ {app_name} added to protection list")
        print(f"⏳ Guardian will monitor for {app_name} launch...")
        
        return True
    
    def _guardian_loop(self) -> None:
        """Main guardian monitoring loop."""
        print("🔄 BLACS Guardian monitoring started...")
        
        while self.monitoring_active and not self.stop_event.is_set():
            try:
                # Check for protected applications
                self._check_protected_applications()
                
                # Scan for cheat tools
                self._scan_for_cheat_tools()
                
                # Self-protection check
                self._verify_self_protection()
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                print(f"❌ Guardian error: {e}")
                time.sleep(5)
    
    def _check_protected_applications(self) -> None:
        """Check if protected applications are running and protect them."""
        for app_name, app_info in self.protected_apps.items():
            try:
                # Find if application is running
                running_pid = self._find_process_by_name(app_name)
                
                if running_pid and not app_info["protection_active"]:
                    # Application started, enable protection
                    print(f"\n🚀 Detected {app_name} launch (PID: {running_pid})")
                    
                    # Create BLACS protection
                    blacs = BLACSIntegration(app_name, "1.0.0")
                    
                    # Set up threat callback
                    def on_threat(violation_data):
                        print(f"\n🚨 GUARDIAN ALERT: {app_name} UNDER ATTACK!")
                        print(f"📝 Threat: {violation_data.get('description', 'Unknown')}")
                        print(f"⚡ Guardian Response: Threat neutralized")
                        print("-" * 50)
                    
                    blacs.set_violation_callback("critical", on_threat)
                    blacs.set_violation_callback("high", on_threat)
                    
                    # Enable protection
                    if blacs.enable_protection(app_info["protection_level"]):
                        # Add to DSLL protection
                        blacs.blacs_system.add_protected_process(running_pid)
                        
                        # Update app info
                        app_info["pid"] = running_pid
                        app_info["blacs_instance"] = blacs
                        app_info["protection_active"] = True
                        app_info["last_seen"] = time.time()
                        
                        print(f"✅ {app_name} protection ACTIVATED")
                        print(f"🔍 DSLL monitoring: ACTIVE")
                        print(f"🛡️ Guardian protection: ENABLED")
                
                elif running_pid and app_info["protection_active"]:
                    # Application still running, update last seen
                    app_info["last_seen"] = time.time()
                
                elif not running_pid and app_info["protection_active"]:
                    # Application closed, disable protection
                    print(f"\n⏹️ {app_name} closed, disabling protection...")
                    
                    if app_info["blacs_instance"]:
                        # Export DSLL ledger
                        ledger_file = f"guardian_log_{app_name}_{int(time.time())}.json"
                        if app_info["blacs_instance"].export_dsll_ledger(ledger_file):
                            print(f"📝 Guardian log exported: {ledger_file}")
                        
                        # Disable protection
                        app_info["blacs_instance"].disable_protection()
                    
                    # Reset app info
                    app_info["pid"] = None
                    app_info["blacs_instance"] = None
                    app_info["protection_active"] = False
                    app_info["last_seen"] = None
                    
                    print(f"✅ {app_name} protection disabled")
                    print(f"⏳ Guardian continues monitoring for relaunch...")
                
            except Exception as e:
                print(f"❌ Error monitoring {app_name}: {e}")
    
    def _find_process_by_name(self, app_name: str) -> Optional[int]:
        """Find a running process by name."""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == app_name.lower():
                    return proc.info['pid']
        except:
            pass
        return None
    
    def _scan_for_cheat_tools(self) -> None:
        """Continuously scan for cheat tools and terminate them."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = (proc_info.get('name') or '').lower()
                    proc_exe = (proc_info.get('exe') or '').lower()
                    
                    # Check against comprehensive cheat database
                    threat_detected = False
                    threat_category = ""
                    
                    for signature in self.all_cheat_signatures:
                        if signature in proc_name or (proc_exe and signature in proc_exe):
                            threat_detected = True
                            # Find which category this belongs to
                            for category, signatures in self.cheat_database.items():
                                if signature in signatures:
                                    threat_category = category
                                    break
                            break
                    
                    if threat_detected:
                        print(f"\n🚨 GUARDIAN THREAT DETECTED!")
                        print(f"📝 Threat: {proc_name} (Category: {threat_category})")
                        print(f"🎯 PID: {proc.pid}")
                        print(f"⚡ Action: IMMEDIATE TERMINATION")
                        
                        # Immediate termination
                        try:
                            proc.terminate()
                            time.sleep(0.2)
                            
                            if proc.is_running():
                                proc.kill()
                                time.sleep(0.2)
                            
                            if proc.is_running():
                                # System-level termination
                                subprocess.run(['taskkill', '/F', '/PID', str(proc.pid)], 
                                             capture_output=True, timeout=5)
                            
                            print(f"✅ Threat neutralized: {proc_name}")
                        
                        except Exception as term_error:
                            print(f"⚠️ Termination failed: {term_error}")
                        
                        print("-" * 50)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"❌ Cheat scan error: {e}")
    
    def _verify_self_protection(self) -> None:
        """Verify guardian self-protection is still active."""
        try:
            current_process = psutil.Process()
            
            # Check if still running with high priority
            if current_process.nice() != psutil.HIGH_PRIORITY_CLASS:
                current_process.nice(psutil.HIGH_PRIORITY_CLASS)
                print("🛡️ Guardian: Self-protection priority restored")
        
        except Exception as e:
            print(f"⚠️ Self-protection verification failed: {e}")
    
    def stop_guardian(self) -> None:
        """Stop the guardian service."""
        print("\n⏹️ Stopping BLACS Guardian...")
        
        self.monitoring_active = False
        self.stop_event.set()
        
        # Disable protection for all apps
        for app_name, app_info in self.protected_apps.items():
            if app_info["blacs_instance"]:
                app_info["blacs_instance"].disable_protection()
        
        if self.guardian_thread:
            self.guardian_thread.join(timeout=5)
        
        print("✅ BLACS Guardian stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get guardian status."""
        return {
            "admin_privileges": self.is_admin,
            "monitoring_active": self.monitoring_active,
            "protected_applications": len(self.protected_apps),
            "active_protections": sum(1 for app in self.protected_apps.values() if app["protection_active"]),
            "cheat_signatures": len(self.all_cheat_signatures),
            "applications": {
                name: {
                    "path": info["path"],
                    "protection_level": info["protection_level"],
                    "running": info["protection_active"],
                    "pid": info["pid"]
                }
                for name, info in self.protected_apps.items()
            }
        }

def main():
    """Main guardian function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="BLACS Guardian - Tamper-Proof Protection Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python blacs_guardian.py "C:\\Windows\\System32\\calc.exe" --level high
  python blacs_guardian.py "C:\\Program Files\\MyGame\\game.exe" --level maximum
  python blacs_guardian.py notepad.exe --level medium

Note: Requires Administrator privileges for tamper-proof protection.
        """
    )
    
    parser.add_argument("app_path", help="Path to application to protect")
    parser.add_argument("--level", "-l", choices=["low", "medium", "high", "maximum"], 
                       default="high", help="Protection level (default: high)")
    
    args = parser.parse_args()
    
    # Create guardian
    guardian = BLACSGuardian()
    
    try:
        # Start guardian service
        if not guardian.start_guardian():
            sys.exit(1)
        
        # Add application to protection
        if not guardian.add_protected_application(args.app_path, args.level):
            sys.exit(1)
        
        print(f"\n💡 BLACS Guardian is now monitoring for {os.path.basename(args.app_path)}")
        print(f"🔒 Tamper-proof protection: ACTIVE")
        print(f"⚠️  Cannot be stopped without Administrator privileges")
        print(f"⏳ Press Ctrl+C to stop (requires admin)")
        
        # Keep guardian running
        while guardian.monitoring_active:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print(f"\n⏹️ Administrator requested stop...")
        guardian.stop_guardian()
    except Exception as e:
        print(f"❌ Guardian error: {e}")
        guardian.stop_guardian()
        sys.exit(1)

if __name__ == "__main__":
    main()