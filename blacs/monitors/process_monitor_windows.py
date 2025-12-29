"""
Windows Process Monitor component for BLACS.

Simplified Windows process monitoring with extreme cheat detection.
"""

import time
import psutil
import threading
import subprocess
from typing import List, Dict, Any, Optional

from ..core.interfaces import ProcessMonitorInterface
from ..core.data_models import (
    ProcessInfo, WindowsProcessInfo, ProcessAnalysis, Violation, ViolationSeverity
)

# Import JSON configuration
try:
    from config_manager import get_config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False


class WindowsProcessMonitor(ProcessMonitorInterface):
    """Windows-specific process monitoring component."""
    
    def __init__(self, scan_interval: float = 2.0):
        """Initialize the Windows process monitor."""
        super().__init__("WindowsProcessMonitor")
        
        # Protection level (will be set by Guardian)
        self.protection_level = None
        
        # Load JSON configuration
        if CONFIG_AVAILABLE:
            self.config = get_config()
            monitor_config = self.config.get_monitor_config("process_monitor")
            system_protection = self.config.get("advanced_settings.system_protection", {})
            
            self.scan_interval = monitor_config.get("settings", {}).get("scan_interval", 2.0)
            self.auto_terminate_threats = monitor_config.get("settings", {}).get("auto_terminate_threats", True)
            self.scan_mode = monitor_config.get("settings", {}).get("scan_mode", "malicious_only")
            self.ignore_system_processes = system_protection.get("ignore_system_processes", True)
            self.focus_on_target = monitor_config.get("settings", {}).get("focus_on_target", True)
            
            # Load only malicious signatures from JSON config
            self.malicious_signatures = set()
            signature_db = self.config.get("threat_detection.signature_database", {})
            for category, signatures in signature_db.items():
                if isinstance(signatures, list):
                    self.malicious_signatures.update(signatures)
            
            # System process patterns to ignore
            self.system_process_patterns = set(system_protection.get("system_process_patterns", []))
        else:
            # Fallback configuration
            self.scan_interval = scan_interval
            self.auto_terminate_threats = True
            self.scan_mode = "malicious_only"
            self.ignore_system_processes = True
            self.focus_on_target = True
            self._load_fallback_signatures()
        
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Process baseline
        self.baseline_processes: Dict[int, WindowsProcessInfo] = {}
        self.baseline_established = False
        
        # Target process tracking
        self.target_process_name = None
        self.target_process_pid = None
        
        # Process baseline
        self.baseline_processes: Dict[int, WindowsProcessInfo] = {}
        self.baseline_established = False
        
        # EXTREME DETECTION: Comprehensive cheat tool database (ENHANCED)
        self.suspicious_names = {
            # ===== MEMORY EDITORS & CHEAT ENGINES =====
            "cheatengine", "cheat engine", "cheat-engine", "ce", "ce64", "ce32",
            "artmoney", "artmoneypro", "art money", "gameguardian", "gg", "guardian",
            "memoryeditor", "memory editor", "memoryhacker", "memory hacker",
            "memhack", "mem hack", "tsearch", "t-search", "scanmem", "scan mem",
            "memoryviewer", "memory viewer", "memview", "hexeditor", "hex editor",
            "memorypatching", "memory patching", "mempatch", "mem patch",
            "gameconqueror", "game conqueror", "memwatch", "mem watch",
            "memoryscanner", "memory scanner", "memscan", "mem scan", "ramhack", "ram hack",
            "ramcheat", "ram cheat", "memtool", "mem tool", "memorymanipulator", "memory manipulator",
            
            # ===== DEBUGGERS & ANALYSIS TOOLS =====
            "ollydbg", "olly", "x64dbg", "x32dbg", "x96dbg", "xdbg",
            "ida", "idapro", "ida pro", "idafree", "ida free", "hexrays",
            "windbg", "win dbg", "kd", "cdb", "ntsd", "gdb", "lldb",
            "processhacker", "process hacker", "processhacker2", "ph", "ph2",
            "systemexplorer", "system explorer", "procexp", "process explorer",
            "apimonitor", "api monitor", "detours", "easyhook", "minhook",
            "rohitab", "immunity", "immunitydebugger", "immunity debugger",
            "radare2", "r2", "ghidra", "binaryninja", "binary ninja",
            "hopper", "disassembler", "decompiler", "reverser", "reverse",
            "softice", "soft ice", "syser", "syser debugger", "winapi", "ntapi",
            
            # ===== INJECTION & HOOKING TOOLS =====
            "injector", "inject", "dllinjector", "dll injector", "processinjector",
            "process injector", "codecave", "code cave", "hooklib", "hook lib",
            "apihook", "api hook", "dethook", "winapi", "ntapi", "kernel32",
            "setwindowshook", "getprocaddress", "loadlibrary", "freelibrary",
            "virtualallocex", "writeprocessmemory", "readprocessmemory",
            "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
            "manualmap", "manual map", "reflectivedll", "reflective dll",
            
            # ===== SPEED HACKS & TIME MANIPULATION =====
            "speedhack", "speed hack", "gamespeed", "game speed", "timescale",
            "time scale", "clockblocker", "clock blocker", "timestop", "time stop",
            "speedgear", "speed gear", "hourglass", "hour glass", "timeshift",
            "time shift", "acceleration", "accelerator", "fps", "framerate",
            "tickrate", "tick rate", "timer", "timing", "temporal", "chrono",
            
            # ===== TRAINERS & GAME MODIFIERS =====
            "trainer", "gametrainer", "game trainer", "fling", "flingtrain",
            "mrantifun", "mr antifun", "cheathappens", "cheat happens", "ch",
            "wemod", "we mod", "plitch", "megadev", "mega dev", "fearless",
            "fearlessrevolution", "fearless revolution", "codex", "skidrow",
            "reloaded", "prophet", "steampunks", "goldberg", "smartsteamemu",
            "greenlight", "ali213", "3dm", "cpy", "plaza", "hoodlum",
            
            # ===== AUTOMATION & BOTS =====
            "autoclicker", "auto clicker", "autoclick", "auto click", "clickbot",
            "click bot", "mousebot", "mouse bot", "keybot", "key bot", "inputbot",
            "input bot", "autohotkey", "ahk", "macro", "macrorecorder", "macro recorder",
            "jitbit", "ghost mouse", "ghostmouse", "perfect automation", "automation",
            "bot", "botter", "farming", "grinder", "aimbot", "aim bot", "wallhack",
            "wall hack", "esp", "triggerbot", "trigger bot", "bhop", "bunny hop",
            
            # ===== NETWORK & PACKET MANIPULATION =====
            "wireshark", "wire shark", "fiddler", "burpsuite", "burp suite",
            "networkminer", "network miner", "tcpdump", "tcp dump", "packetsender",
            "packet sender", "networkhack", "network hack", "lagswitch", "lag switch",
            "netlimiter", "net limiter", "packeteditor", "packet editor", "mitm",
            "man in the middle", "proxy", "sniffer", "interceptor", "tamper",
            
            # ===== CRACKING & REVERSE ENGINEERING =====
            "crack", "cracker", "keygen", "key gen", "patch", "patcher", "loader",
            "activator", "bypass", "unlocker", "remover", "killer", "disabler",
            "unpacker", "protector", "obfuscator", "deobfuscator", "strings",
            "hexedit", "hex edit", "binedit", "bin edit", "resource", "reshacker",
            "res hacker", "pe", "portable executable", "elf", "mach-o", "binary",
            
            # ===== MODDING & GAME MODIFICATION =====
            "mod", "mods", "modding", "modder", "modification", "modifier",
            "reshade", "re shade", "sweetfx", "enb", "enbseries", "enb series",
            "asi", "asiloader", "asi loader", "scripthook", "script hook", "cleo",
            "samp", "multitheft", "multi theft", "gtasa", "gta sa", "vcmp",
            "mta", "multitheftauto", "openiv", "open iv", "modloader", "mod loader",
            
            # ===== MOBILE/APK HACKING TOOLS =====
            "gameguardian", "gg", "guardian", "lucky patcher", "luckypatcher",
            "freedom", "creehack", "cree hack", "game killer", "gamekiller",
            "sb game hacker", "sbgamehacker", "cheat droid", "cheatdroid",
            "game cih", "gamecih", "xmodgames", "xmod games", "ihackedit",
            "ifile", "filza", "apktool", "apk tool", "dex2jar", "jadx",
            "frida", "xposed", "magisk", "root", "jailbreak", "cydia",
            "substrate", "hooking", "runtime", "manipulation", "bytecode",
            "bluestacks", "nox", "memu", "ldplayer", "gameloop", "phoenix os",
            "hack", "hacker", "hacking", "cheat", "cheater", "cheating", "exploit",
            "exploiter", "exploiting", "glitch", "glitcher", "glitching", "abuse",
            "abuser", "abusing", "unfair", "advantage", "enhancement", "enhancer",
            "booster", "boost", "amplifier", "multiplier", "unlimited", "infinite",
            "godmode", "god mode", "noclip", "no clip", "fly", "flying", "teleport",
            
            # ===== SPECIFIC GAME CHEATS =====
            "aimassist", "aim assist", "recoil", "norecoil", "no recoil", "spread",
            "nospread", "no spread", "radar", "minimap", "xray", "x-ray", "vision",
            "nightvision", "night vision", "thermal", "highlight", "glow", "outline",
            "skeleton", "bones", "hitbox", "hit box", "headshot", "autofire", "auto fire",
            "rapidfire", "rapid fire", "fullbright", "full bright", "gamma", "brightness",
            
            # ===== ANTI-DETECTION & STEALTH =====
            "stealth", "hidden", "invisible", "undetected", "undetectable", "bypass",
            "evade", "evasion", "mask", "masker", "spoof", "spoofer", "fake", "faker",
            "emulator", "virtual", "sandbox", "vm", "vmware", "virtualbox", "qemu",
            "hyperv", "hyper-v", "container", "docker", "wine", "proton", "compatibility",
            
            # ===== DEVELOPMENT & TESTING TOOLS (when used maliciously) =====
            "visual studio", "vs", "vscode", "code", "devenv", "msbuild", "cmake",
            "mingw", "gcc", "clang", "python", "java", "javaw", "node", "nodejs",
            "powershell", "cmd", "bash", "sh", "terminal", "console", "command",
            
            # ===== SYSTEM UTILITIES (suspicious when combined) =====
            "taskmgr", "task manager", "regedit", "registry", "msconfig", "services",
            "perfmon", "performance", "resmon", "resource", "procmon", "filemon",
            "regmon", "sysmon", "eventlog", "event log", "wmi", "powershell_ise",
            
            # ===== SPECIFIC CHEAT SOFTWARE BRANDS =====
            "battleye", "eac", "easy anti cheat", "vac", "valve anti cheat", "fairfight",
            "punk buster", "punkbuster", "gameguard", "nprotect", "xigncode", "ricochet",
            "vanguard", "riot vanguard", "faceit", "esea", "cevo", "popflash",
            
            # ===== CRYPTOCURRENCY & MINING (resource abuse) =====
            "miner", "mining", "bitcoin", "ethereum", "crypto", "cryptocurrency",
            "hashrate", "gpu", "cpu", "asic", "pool", "wallet", "blockchain",
            
            # ===== ADDITIONAL SUSPICIOUS PATTERNS =====
            "external", "overlay", "injection", "modification", "manipulation",
            "automation", "simulation", "emulation", "virtualization", "containerization",
            
            # ===== MOBILE/APK HACKING TOOLS =====
            "gameguardian", "gg", "guardian", "lucky patcher", "luckypatcher",
            "freedom", "creehack", "cree hack", "game killer", "gamekiller",
            "sb game hacker", "sbgamehacker", "cheat droid", "cheatdroid",
            "game cih", "gamecih", "xmodgames", "xmod games", "ihackedit",
            "ifile", "filza", "apktool", "apk tool", "dex2jar", "jadx",
            "frida", "xposed", "magisk", "root", "jailbreak", "cydia",
            "substrate", "hooking", "runtime", "manipulation", "bytecode",
            "bluestacks", "nox", "memu", "ldplayer", "gameloop", "phoenix os",
            
            # ===== CRYPTOCURRENCY & MINING =====
            "miner", "mining", "bitcoin", "ethereum", "crypto", "cryptocurrency",
            "hashrate", "gpu", "cpu", "asic", "pool", "wallet", "blockchain",
            "monero", "zcash", "litecoin", "dogecoin", "nicehash", "claymore",
            "phoenixminer", "t-rex", "gminer", "lolminer", "nbminer", "teamredminer"
        }
        
        # EXTREME DETECTION: Suspicious paths (expanded)
        self.suspicious_paths = {
            # Temporary directories
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\",
            "\\programdata\\", "\\users\\public\\", "\\recycle", "\\recycler\\",
            
            # Common cheat tool locations
            "\\desktop\\", "\\downloads\\", "\\documents\\cheats\\", "\\documents\\hacks\\",
            "\\documents\\trainers\\", "\\documents\\mods\\", "\\documents\\cracks\\",
            "\\appdata\\roaming\\", "\\appdata\\local\\", "\\localappdata\\",
            
            # Suspicious folder names
            "\\cheat", "\\hack", "\\trainer", "\\mod", "\\crack", "\\patch",
            "\\bypass", "\\exploit", "\\bot", "\\auto", "\\macro", "\\script",
            "\\inject", "\\hook", "\\debug", "\\reverse", "\\analysis",
            "\\memory", "\\process", "\\dll", "\\api", "\\kernel", "\\system",
            
            # Hidden/system directories
            "\\$recycle.bin\\", "\\system volume information\\", "\\recovery\\",
            "\\boot\\", "\\efi\\", "\\msocache\\", "\\perflogs\\", "\\programdata\\",
            
            # Portable/USB locations
            "\\portable\\", "\\usb\\", "\\removable\\", "\\external\\",
            "d:\\", "e:\\", "f:\\", "g:\\", "h:\\", "i:\\", "j:\\", "k:\\",
            
            # Network/shared locations
            "\\\\", "\\network\\", "\\shared\\", "\\remote\\", "\\ftp\\",
            
            # Development directories (when suspicious)
            "\\source\\", "\\src\\", "\\build\\", "\\bin\\", "\\debug\\",
            "\\release\\", "\\output\\", "\\obj\\", "\\packages\\", "\\node_modules\\"
        }
        
        # EXTREME DETECTION: Comprehensive suspicious executables
        self.suspicious_executables = {
            # ===== CHEAT ENGINES & MEMORY EDITORS =====
            "cheatengine.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
            "ce.exe", "ce64.exe", "ce32.exe", "ce-x64.exe", "ce-x86.exe",
            "artmoney.exe", "artmoneypro.exe", "artmoney64.exe", "artmoney32.exe",
            "gameguardian.exe", "gg.exe", "guardian.exe", "memoryeditor.exe",
            "memoryhacker.exe", "memhack.exe", "tsearch.exe", "scanmem.exe",
            "memoryviewer.exe", "memview.exe", "hexeditor.exe", "memwatch.exe",
            "gameconqueror.exe", "memorypatching.exe", "mempatch.exe",
            
            # ===== DEBUGGERS & ANALYSIS TOOLS =====
            "ollydbg.exe", "olly.exe", "x64dbg.exe", "x32dbg.exe", "x96dbg.exe",
            "ida.exe", "ida64.exe", "ida32.exe", "idapro.exe", "idafree.exe",
            "windbg.exe", "kd.exe", "cdb.exe", "ntsd.exe", "gdb.exe", "lldb.exe",
            "processhacker.exe", "processhacker2.exe", "ph.exe", "ph2.exe",
            "systemexplorer.exe", "procexp.exe", "procexp64.exe", "apimonitor.exe",
            "immunity.exe", "immunitydebugger.exe", "radare2.exe", "r2.exe",
            "ghidra.exe", "binaryninja.exe", "hopper.exe", "disassembler.exe",
            
            # ===== INJECTION & HOOKING TOOLS =====
            "injector.exe", "inject.exe", "dllinjector.exe", "processinjector.exe",
            "codecave.exe", "hooklib.exe", "apihook.exe", "dethook.exe",
            "manualmap.exe", "reflectivedll.exe", "loadlibrary.exe",
            "createremotethread.exe", "virtualallocex.exe", "writeprocessmemory.exe",
            
            # ===== SPEED HACKS & TIME MANIPULATION =====
            "speedhack.exe", "gamespeed.exe", "timescale.exe", "clockblocker.exe",
            "timestop.exe", "speedgear.exe", "hourglass.exe", "timeshift.exe",
            "acceleration.exe", "accelerator.exe", "timer.exe", "chrono.exe",
            
            # ===== TRAINERS & GAME MODIFIERS =====
            "trainer.exe", "gametrainer.exe", "fling.exe", "flingtrain.exe",
            "mrantifun.exe", "cheathappens.exe", "ch.exe", "wemod.exe",
            "plitch.exe", "megadev.exe", "fearless.exe", "fearlessrevolution.exe",
            "codex.exe", "skidrow.exe", "reloaded.exe", "prophet.exe",
            "steampunks.exe", "goldberg.exe", "smartsteamemu.exe",
            
            # ===== AUTOMATION & BOTS =====
            "autoclicker.exe", "autoclick.exe", "clickbot.exe", "mousebot.exe",
            "keybot.exe", "inputbot.exe", "autohotkey.exe", "ahk.exe",
            "macro.exe", "macrorecorder.exe", "jitbit.exe", "ghostmouse.exe",
            "automation.exe", "bot.exe", "botter.exe", "aimbot.exe",
            "wallhack.exe", "esp.exe", "triggerbot.exe", "bhop.exe",
            
            # ===== NETWORK & PACKET MANIPULATION =====
            "wireshark.exe", "fiddler.exe", "burpsuite.exe", "networkminer.exe",
            "tcpdump.exe", "packetsender.exe", "networkhack.exe", "lagswitch.exe",
            "netlimiter.exe", "packeteditor.exe", "sniffer.exe", "interceptor.exe",
            
            # ===== CRACKING & REVERSE ENGINEERING =====
            "crack.exe", "cracker.exe", "keygen.exe", "patch.exe", "patcher.exe",
            "loader.exe", "activator.exe", "bypass.exe", "unlocker.exe",
            "remover.exe", "killer.exe", "disabler.exe", "unpacker.exe",
            "protector.exe", "obfuscator.exe", "deobfuscator.exe", "strings.exe",
            "hexedit.exe", "binedit.exe", "reshacker.exe", "resource.exe",
            
            # ===== MODDING & GAME MODIFICATION =====
            "mod.exe", "mods.exe", "modding.exe", "modifier.exe", "reshade.exe",
            "sweetfx.exe", "enb.exe", "enbseries.exe", "asiloader.exe",
            "scripthook.exe", "cleo.exe", "samp.exe", "multitheft.exe",
            "openiv.exe", "modloader.exe", "gtasa.exe", "vcmp.exe", "mta.exe",
            
            # ===== GENERAL HACKING & CHEATING =====
            "hack.exe", "hacker.exe", "cheat.exe", "cheater.exe", "exploit.exe",
            "exploiter.exe", "glitch.exe", "glitcher.exe", "abuse.exe",
            "enhancement.exe", "enhancer.exe", "booster.exe", "amplifier.exe",
            "unlimited.exe", "infinite.exe", "godmode.exe", "noclip.exe",
            "fly.exe", "teleport.exe", "aimassist.exe", "norecoil.exe",
            
            # ===== ANTI-DETECTION & STEALTH =====
            "stealth.exe", "hidden.exe", "invisible.exe", "undetected.exe",
            "bypass.exe", "evade.exe", "mask.exe", "spoof.exe", "fake.exe",
            "emulator.exe", "virtual.exe", "sandbox.exe", "vm.exe",
            
            # ===== CRYPTOCURRENCY MINERS =====
            "miner.exe", "mining.exe", "bitcoin.exe", "ethereum.exe",
            "crypto.exe", "hashrate.exe", "pool.exe", "wallet.exe",
            
            # ===== ADDITIONAL PATTERNS =====
            "external.exe", "overlay.exe", "injection.exe", "modification.exe",
            "manipulation.exe", "automation.exe", "simulation.exe"
        }
        
        # Known legitimate Windows processes (whitelist)
        self.legitimate_processes = {
            "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "dwm.exe", "conhost.exe", "audiodg.exe", "spoolsv.exe"
        }
        
        # Process baseline
        self.baseline_processes: Dict[int, WindowsProcessInfo] = {}
        self.baseline_established = False
    
    def set_target_process(self, process_name: str, process_pid: int = None):
        """Set the target process to protect."""
        self.target_process_name = process_name.lower()
        self.target_process_pid = process_pid
        print(f"🎯 Process Monitor: Targeting {process_name}")
    
    def _load_fallback_signatures(self) -> None:
        """Load fallback malicious signatures when JSON config is not available."""
        # Only the most obvious cheat tools
        self.malicious_signatures = {
            # Exact executable names only
            "cheatengine.exe", "ce.exe", "ce64.exe", "ce32.exe",
            "artmoney.exe", "artmoneypro.exe", "gameguardian.exe",
            "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "processhacker.exe",
            "injector.exe", "dllinjector.exe", "speedhack.exe",
            "trainer.exe", "gametrainer.exe", "autoclicker.exe", "aimbot.exe"
        }
        
        # System process patterns to ignore
        self.system_process_patterns = {
            "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "dwm.exe", "conhost.exe", "audiodg.exe", "spoolsv.exe",
            "taskmgr.exe", "taskhost.exe", "taskhostw.exe"
        }
    
    def start_monitoring(self) -> None:
        """Start the process monitoring."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.stop_event.clear()
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop the process monitoring."""
        if self.monitoring_thread:
            self.stop_event.set()
            self.monitoring_thread.join(timeout=2.0)
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop - ONLY scans for malicious processes."""
        while not self.stop_event.is_set():
            try:
                # Only scan for malicious processes, ignore everything else
                self._scan_for_malicious_processes_only()
                
                time.sleep(self.scan_interval)
                
            except Exception as e:
                # Log error and continue monitoring
                violation = Violation(
                    component=self.name,
                    severity=ViolationSeverity.LOW,
                    description=f"Process monitoring error: {str(e)}",
                    evidence={"error_type": type(e).__name__}
                )
                self.violations.append(violation)
                time.sleep(self.scan_interval)
    
    def _scan_for_malicious_processes_only(self) -> None:
        """Scan for malicious processes with PRECISE matching and comprehensive logging."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                try:
                    proc_info = proc.info
                    proc_name = (proc_info.get('name') or '').lower()
                    proc_exe = (proc_info.get('exe') or '').lower()
                    
                    # Skip if no process name
                    if not proc_name:
                        continue
                    
                    # Log ALL processes for comprehensive monitoring
                    self._log_process_activity(proc_info, "process_scan")
                    
                    # Skip system processes and Windows services
                    if self._is_system_process(proc_name) or self._is_windows_service(proc_name):
                        continue
                    
                    # PRECISE MATCHING: Only exact executable names
                    is_malicious = False
                    detected_signature = None
                    threat_category = None
                    
                    # Check against malicious signatures with ENHANCED matching
                    for signature in self.malicious_signatures:
                        # Remove .exe extension from signature for comparison
                        sig_name = signature.replace('.exe', '').lower()
                        
                        # Enhanced matching for CheatEngine variants
                        if sig_name == 'cheatengine':
                            # Match any CheatEngine variant (cheatengine, cheatengine-x86_64, etc.)
                            if 'cheatengine' in proc_name:
                                is_malicious = True
                                detected_signature = signature
                                threat_category = self._get_threat_category(signature)
                                print(f"🎯 CheatEngine variant detected: {proc_name} matches {signature}")
                                break
                        elif sig_name == 'artmoney':
                            # Match any ArtMoney variant
                            if 'artmoney' in proc_name:
                                is_malicious = True
                                detected_signature = signature
                                threat_category = self._get_threat_category(signature)
                                break
                        elif sig_name == 'processhacker':
                            # Match Process Hacker variants
                            if 'processhacker' in proc_name or proc_name.startswith('ph'):
                                is_malicious = True
                                detected_signature = signature
                                threat_category = self._get_threat_category(signature)
                                break
                        elif sig_name in ['ollydbg', 'x64dbg', 'x32dbg']:
                            # Match debugger variants
                            if sig_name in proc_name:
                                is_malicious = True
                                detected_signature = signature
                                threat_category = self._get_threat_category(signature)
                                break
                        else:
                            # Exact match for other signatures
                            if sig_name == proc_name or signature == proc_name:
                                is_malicious = True
                                detected_signature = signature
                                threat_category = self._get_threat_category(signature)
                                break
                    
                    if is_malicious:
                        # Log the threat detection
                        self._log_threat_detection(proc_info, detected_signature, threat_category)
                        
                        print(f"\n🚨 CONFIRMED CHEAT TOOL DETECTED!")
                        print(f"📝 Process: {proc_name}")
                        print(f"🎯 PID: {proc.pid}")
                        print(f"🔍 Signature: {detected_signature}")
                        print(f"📂 Category: {threat_category}")
                        
                        # Create violation
                        violation = Violation(
                            component=self.name,
                            severity=ViolationSeverity.CRITICAL,
                            description=f"Confirmed cheat tool detected: {proc_name}",
                            evidence={
                                "process_name": proc_name,
                                "process_pid": proc.pid,
                                "executable_path": proc_exe,
                                "detected_signature": detected_signature,
                                "threat_category": threat_category,
                                "detection_method": "exact_signature_match",
                                "command_line": proc_info.get('cmdline', []),
                                "username": proc_info.get('username', 'unknown')
                            }
                        )
                        self.violations.append(violation)
                        
                        # Only terminate confirmed cheat tools
                        if self.auto_terminate_threats and self._is_confirmed_cheat_tool(proc_name):
                            print(f"⚡ Action: TERMINATING CONFIRMED CHEAT TOOL")
                            self._terminate_malicious_process(proc, proc_name)
                        else:
                            print(f"⚡ Action: LOGGED (termination disabled or uncertain)")
                        
                        print("-" * 50)
                    else:
                        # Log non-malicious processes for monitoring
                        self._log_process_activity(proc_info, "legitimate_process")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"❌ Process scan error: {e}")
            self._log_error("process_scan_error", str(e))
    
    def _is_system_process(self, process_name: str) -> bool:
        """Check if a process is a system process that should be ignored."""
        process_name = process_name.lower()
        
        # Check against system process patterns
        for pattern in self.system_process_patterns:
            if pattern.lower() == process_name:
                return True
        
        # Check for Windows system paths
        if any(sys_name in process_name for sys_name in ['system32', 'syswow64', 'windows']):
            return True
        
        # Check for Microsoft signed processes (basic heuristic)
        if any(ms_name in process_name for ms_name in ['microsoft', 'windows', 'ms']):
            return True
        
        return False
    
    def _is_windows_service(self, process_name: str) -> bool:
        """Check if process is a Windows service that should never be terminated."""
        windows_services = {
            'udclientservice.exe', 'mpdefendercoreservice.exe', 'rtkaudioservice64.exe',
            'nvcontainer.exe', 'nvdisplay.container.exe', 'audiodg.exe',
            'wuauclt.exe', 'trustedinstaller.exe', 'tiworker.exe',
            'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
            'wmiprvse.exe', 'dllhost.exe', 'rundll32.exe', 'regsvr32.exe',
            'msiexec.exe', 'spoolsv.exe', 'printfilterpipelinesvc.exe',
            'windefend.exe', 'msmpeng.exe', 'antimalware service executable',
            'defender.exe', 'securityhealthservice.exe', 'securityhealthsystray.exe'
        }
        return process_name.lower() in windows_services
    
    def _is_confirmed_cheat_tool(self, process_name: str) -> bool:
        """Check if this is a confirmed cheat tool that should be terminated."""
        confirmed_cheat_tools = {
            'cheatengine.exe', 'cheatengine-x86_64.exe', 'cheatengine-i386.exe',
            'artmoney.exe', 'artmoneypro.exe', 'gameguardian.exe',
            'ollydbg.exe', 'x64dbg.exe', 'x32dbg.exe', 'processhacker.exe',
            'injector.exe', 'dllinjector.exe', 'speedhack.exe',
            'trainer.exe', 'gametrainer.exe', 'autoclicker.exe', 'aimbot.exe'
        }
        return process_name.lower() in confirmed_cheat_tools
    
    def _get_threat_category(self, signature: str) -> str:
        """Get the category of a threat signature."""
        if CONFIG_AVAILABLE:
            signature_db = self.config.get("threat_detection.signature_database", {})
            for category, signatures in signature_db.items():
                if isinstance(signatures, list) and signature in signatures:
                    return category
        return "unknown"
    
    def _log_process_activity(self, proc_info: dict, activity_type: str) -> None:
        """Log process activity for comprehensive monitoring."""
        try:
            import logging
            import json
            from datetime import datetime
            
            # Configure logging if not already done
            if not hasattr(self, '_logger_configured'):
                # Ensure log directory exists
                log_file = 'blacs_process_monitor.log'
                
                # Configure logging with proper formatting
                logging.basicConfig(
                    filename=log_file,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filemode='a'  # Append mode
                )
                
                # Also log to console for immediate feedback
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.INFO)
                formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                console_handler.setFormatter(formatter)
                
                # Get the root logger and add console handler
                root_logger = logging.getLogger()
                if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
                    root_logger.addHandler(console_handler)
                
                self._logger_configured = True
                
                # Log initialization
                logging.info("BLACS Process Monitor logging initialized")
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "activity_type": activity_type,
                "process_name": proc_info.get('name', 'unknown'),
                "process_id": proc_info.get('pid', 0),
                "executable_path": proc_info.get('exe', 'unknown'),
                "command_line": proc_info.get('cmdline', []),
                "username": proc_info.get('username', 'unknown'),
                "create_time": proc_info.get('create_time', 0)
            }
            
            logging.info(f"PROCESS_ACTIVITY: {json.dumps(log_entry)}")
            
            # Also print to console for immediate feedback
            if activity_type == "threat_detected":
                print(f"📝 LOGGED THREAT: {proc_info.get('name', 'unknown')} (PID: {proc_info.get('pid', 0)})")
            
        except Exception as e:
            print(f"⚠️ Logging error: {e}")
            # Fallback: print to console
            print(f"📝 PROCESS: {proc_info.get('name', 'unknown')} - {activity_type}")
    
    def _log_threat_detection(self, proc_info: dict, signature: str, category: str) -> None:
        """Log threat detection with full details."""
        try:
            import logging
            import json
            from datetime import datetime
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "THREAT_DETECTED",
                "process_name": proc_info.get('name', 'unknown'),
                "process_id": proc_info.get('pid', 0),
                "executable_path": proc_info.get('exe', 'unknown'),
                "command_line": proc_info.get('cmdline', []),
                "username": proc_info.get('username', 'unknown'),
                "detected_signature": signature,
                "threat_category": category,
                "severity": "CRITICAL",
                "action_taken": "TERMINATE" if self._is_confirmed_cheat_tool(proc_info.get('name', '')) else "LOG_ONLY"
            }
            
            logging.critical(f"THREAT_DETECTION: {json.dumps(log_entry)}")
            
            # Also print to console for immediate visibility
            print(f"🚨 THREAT LOGGED: {proc_info.get('name', 'unknown')} - {signature}")
            
        except Exception as e:
            print(f"⚠️ Threat logging error: {e}")
            # Fallback: print to console
            print(f"🚨 THREAT: {proc_info.get('name', 'unknown')} detected as {signature}")
    
    def _log_error(self, error_type: str, error_message: str) -> None:
        """Log errors for debugging."""
        try:
            import logging
            import json
            from datetime import datetime
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "ERROR",
                "error_type": error_type,
                "error_message": error_message
            }
            
            logging.error(f"SYSTEM_ERROR: {json.dumps(log_entry)}")
            
        except Exception:
            pass
    
    def _terminate_malicious_process(self, proc: psutil.Process, proc_name: str) -> None:
        """Terminate a confirmed malicious process."""
        try:
            # Immediate termination for malicious processes
            proc.terminate()
            time.sleep(0.2)
            
            if proc.is_running():
                proc.kill()
                time.sleep(0.2)
            
            if proc.is_running():
                # System-level termination (Windows)
                try:
                    subprocess.run(['taskkill', '/F', '/PID', str(proc.pid)], 
                                 capture_output=True, timeout=5)
                except:
                    pass
            
            # Verify termination
            time.sleep(0.3)
            if not proc.is_running():
                print(f"✅ Successfully terminated malicious process: {proc_name}")
            else:
                print(f"⚠️  Malicious process still running: {proc_name} (may be protected)")
        
        except Exception as e:
            print(f"⚠️  Failed to terminate malicious process {proc_name}: {e}")
    
    def _scan_for_active_threats(self) -> List[Violation]:
        """EXTREME: Real-time scanning for active cheat threats."""
        violations = []
        
        try:
            # Scan for processes that match known cheat signatures
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    proc_name = (proc_info.get('name') or '').lower()
                    
                    # High-priority threat detection
                    high_priority_threats = [
                        'cheatengine', 'artmoney', 'gameguardian', 'memoryeditor',
                        'ollydbg', 'x64dbg', 'processhacker', 'injector'
                    ]
                    
                    for threat in high_priority_threats:
                        if threat in proc_name:
                            # Immediate termination for high-priority threats
                            violations.append(Violation(
                                component=self.name,
                                severity=ViolationSeverity.CRITICAL,
                                description=f"High-priority cheat threat detected: {proc_name}",
                                evidence={
                                    "threat_type": threat,
                                    "process_name": proc_name,
                                    "process_pid": proc.pid,
                                    "detection_method": "real_time_scan",
                                    "threat_priority": "high"
                                }
                            ))
                            
                            # Attempt immediate termination
                            try:
                                proc.terminate()
                                print(f"🚫 BLACS EXTREME: Immediately terminated high-priority threat: {proc_name}")
                            except:
                                try:
                                    proc.kill()
                                    print(f"🚫 BLACS EXTREME: Force killed high-priority threat: {proc_name}")
                                except:
                                    print(f"⚠️  BLACS: Could not terminate high-priority threat: {proc_name}")
                            
                            break
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            violations.append(Violation(
                component=self.name,
                severity=ViolationSeverity.LOW,
                description=f"Active threat scanning error: {str(e)}",
                evidence={"error_type": type(e).__name__}
            ))
        
        return violations
    
    def enumerate_processes(self) -> List[ProcessInfo]:
        """
        Enumerate all running processes using Windows APIs.
        
        Returns:
            List of ProcessInfo objects for all running processes
        """
        processes = []
        
        try:
            # Use psutil for cross-platform process enumeration
            # In a real implementation, this would use Toolhelp32 APIs directly
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'username']):
                try:
                    proc_info = proc.info
                    
                    # Get Windows-specific information
                    privileges = self._get_process_privileges(proc)
                    
                    # Create Windows-specific process info
                    windows_proc = WindowsProcessInfo(
                        pid=proc_info['pid'],
                        name=proc_info['name'] or 'unknown',
                        executable_path=proc_info['exe'] or '',
                        start_time=proc_info['create_time'] or time.time(),
                        process_name=proc_info['name'] or 'unknown',
                        privileges=privileges
                    )
                    
                    processes.append(windows_proc)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Process disappeared or access denied, skip it
                    continue
                    
        except Exception as e:
            # Log enumeration error
            violation = Violation(
                component=self.name,
                severity=ViolationSeverity.LOW,
                description=f"Process enumeration error: {str(e)}",
                evidence={"error_type": type(e).__name__}
            )
            self.violations.append(violation)
        
        return processes
    
    def _get_process_privileges(self, proc: psutil.Process) -> List[str]:
        """Get process privileges (simplified implementation)."""
        privileges = []
        
        try:
            # Check if process is running as administrator/system
            if proc.username():
                username = proc.username().lower()
                if 'system' in username or 'administrator' in username:
                    privileges.append("elevated")
                else:
                    privileges.append("user")
            
            # Check process priority (high priority might indicate system process)
            try:
                if proc.nice() < 0:  # Higher than normal priority
                    privileges.append("high_priority")
            except (psutil.AccessDenied, AttributeError):
                pass
                
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            privileges.append("access_denied")
        
        return privileges
    
    def analyze_process_characteristics(self, processes: List[ProcessInfo]) -> List[ProcessAnalysis]:
        """
        Analyze characteristics of processes for suspicious behavior.
        
        Args:
            processes: List of ProcessInfo objects to analyze
            
        Returns:
            List of ProcessAnalysis results
        """
        analysis_results = []
        
        for process in processes:
            if not isinstance(process, WindowsProcessInfo):
                continue
            
            risk_score = 0.0
            suspicious_indicators = []
            
            # Check if process is in legitimate whitelist
            name_lower = (process.name or '').lower()
            if name_lower in self.legitimate_processes:
                # Legitimate system process, lower risk
                risk_score = 0.0
            else:
                # EXTREME DETECTION: Multiple detection layers
                
                # Layer 1: Exact name matching (highest priority)
                for suspicious_name in self.suspicious_names:
                    if suspicious_name == name_lower:
                        risk_score += 0.8  # Very high risk for exact matches
                        suspicious_indicators.append(f"exact_name_match:{suspicious_name}")
                        break
                
                # Layer 2: Partial name matching (medium priority)
                for suspicious_name in self.suspicious_names:
                    if len(suspicious_name) > 4 and suspicious_name in name_lower:
                        risk_score += 0.4
                        suspicious_indicators.append(f"partial_name_match:{suspicious_name}")
                
                # Layer 3: Executable name analysis
                if process.executable_path:
                    exe_name = (process.executable_path.split('\\')[-1] if process.executable_path else '').lower()
                    if exe_name in self.suspicious_executables:
                        risk_score += 0.6
                        suspicious_indicators.append(f"suspicious_executable:{exe_name}")
                
                # Layer 4: Path analysis (multiple checks)
                if process.executable_path:
                    path_lower = (process.executable_path or '').lower()
                    
                    # Check for suspicious paths
                    for suspicious_path in self.suspicious_paths:
                        if suspicious_path in path_lower:
                            risk_score += 0.3
                            suspicious_indicators.append(f"suspicious_path:{suspicious_path}")
                    
                    # Check for system directory masquerading
                    if ("\\system32\\" in path_lower or "\\syswow64\\" in path_lower) and name_lower not in self.legitimate_processes:
                        risk_score += 0.5
                        suspicious_indicators.append("system_directory_masquerading")
                    
                    # Check for unsigned executables in system directories
                    if "\\windows\\" in path_lower and name_lower not in self.legitimate_processes:
                        risk_score += 0.4
                        suspicious_indicators.append("unsigned_system_executable")
                
                # Layer 5: Process behavior analysis
                if "elevated" in process.privileges and risk_score > 0:
                    risk_score += 0.2
                    suspicious_indicators.append("elevated_privileges_suspicious")
                
                # Layer 6: Process name pattern analysis
                proc_name = process.name or ''
                
                # Check for suspicious characters
                if any(char in proc_name for char in ['@', '#', '$', '%', '&', '*', '!', '?']):
                    risk_score += 0.15
                    suspicious_indicators.append("unusual_characters_in_name")
                
                # Check for very short or very long process names
                if len(proc_name) <= 2 or len(proc_name) >= 50:
                    risk_score += 0.1
                    suspicious_indicators.append("unusual_name_length")
                
                # Check for numeric-only names (suspicious)
                if proc_name.isdigit():
                    risk_score += 0.2
                    suspicious_indicators.append("numeric_only_name")
                
                # Check for random-looking names
                if len(proc_name) > 8 and not any(word in proc_name.lower() for word in ['windows', 'microsoft', 'system', 'service', 'update']):
                    vowels = sum(1 for c in proc_name.lower() if c in 'aeiou')
                    consonants = sum(1 for c in proc_name.lower() if c.isalpha() and c not in 'aeiou')
                    if vowels > 0 and consonants / vowels > 4:  # Too many consonants
                        risk_score += 0.1
                        suspicious_indicators.append("random_looking_name")
                
                # Layer 7: Multiple word analysis
                name_words = name_lower.replace('-', ' ').replace('_', ' ').split()
                cheat_words = ['cheat', 'hack', 'bot', 'mod', 'crack', 'trainer', 'auto', 'inject', 'hook', 'bypass', 'exploit']
                
                for word in name_words:
                    if word in cheat_words:
                        risk_score += 0.3
                        suspicious_indicators.append(f"cheat_word_detected:{word}")
                
                # Layer 8: File extension analysis (if available)
                if process.executable_path:
                    if not process.executable_path.lower().endswith('.exe'):
                        risk_score += 0.2
                        suspicious_indicators.append("non_exe_executable")
                
                # Layer 9: New process detection (post-baseline)
                if self.baseline_established and process.pid not in self.baseline_processes:
                    if risk_score > 0.2:  # Only flag if already suspicious
                        risk_score += 0.15
                        suspicious_indicators.append("new_suspicious_process")
                
                # Layer 10: Process clustering (multiple suspicious processes)
                if len(suspicious_indicators) >= 3:
                    risk_score += 0.1
                    suspicious_indicators.append("multiple_suspicious_indicators")
                
                # EXTREME: Immediate termination for critical threats
                if risk_score >= 0.9:
                    self._attempt_process_termination(process)
                    suspicious_indicators.append("auto_terminated_critical_threat")
            
            # Normalize risk score to 0-1 range
            risk_score = min(risk_score, 1.0)
            
            analysis = ProcessAnalysis(
                process_info=process,
                risk_score=risk_score,
                suspicious_indicators=suspicious_indicators
            )
            
            analysis_results.append(analysis)
        
        return analysis_results
    
    def _attempt_process_termination(self, process: WindowsProcessInfo) -> None:
        """EXTREME: Aggressively terminate detected cheat processes."""
        try:
            # Find the actual psutil process
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if proc.pid == process.pid:
                    print(f"🚫 BLACS EXTREME: Terminating cheat tool: {process.name} (PID: {process.pid})")
                    
                    # Method 1: Standard termination
                    try:
                        proc.terminate()
                        time.sleep(0.2)
                        
                        if proc.is_running():
                            # Method 2: Force kill
                            proc.kill()
                            time.sleep(0.2)
                        
                        if proc.is_running():
                            # Method 3: System-level termination (Windows)
                            if platform_detector.is_windows:
                                try:
                                    subprocess.run(['taskkill', '/F', '/PID', str(process.pid)], 
                                                 capture_output=True, timeout=5)
                                except:
                                    pass
                        
                        # Verify termination
                        time.sleep(0.3)
                        if not proc.is_running():
                            print(f"✅ BLACS: Successfully terminated cheat tool: {process.name}")
                            
                            # Log the termination
                            violation = Violation(
                                component=self.name,
                                severity=ViolationSeverity.CRITICAL,
                                description=f"Cheat tool terminated: {process.name}",
                                evidence={
                                    "process_name": process.name,
                                    "process_pid": process.pid,
                                    "executable_path": process.executable_path,
                                    "termination_method": "aggressive",
                                    "termination_time": time.time()
                                }
                            )
                            self.violations.append(violation)
                        else:
                            print(f"⚠️  BLACS: Cheat tool still running: {process.name} (may be protected)")
                    
                    except Exception as term_error:
                        print(f"⚠️  BLACS: Termination failed for {process.name}: {str(term_error)}")
                    
                    break
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"⚠️  BLACS: Could not access process {process.name}: {str(e)}")
        except Exception as e:
            print(f"⚠️  BLACS: Unexpected error terminating {process.name}: {str(e)}")
    
    def _detect_process_relationships(self) -> List[Violation]:
        """EXTREME: Detect suspicious process relationships and injection attempts."""
        violations = []
        
        try:
            # Get all current processes
            current_processes = {}
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info
                    current_processes[proc.pid] = proc_info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Analyze process relationships
            for pid, proc_info in current_processes.items():
                proc_name = (proc_info.get('name') or '').lower()
                
                # Check for suspicious parent-child relationships
                ppid = proc_info.get('ppid')
                if ppid and ppid in current_processes:
                    parent_info = current_processes[ppid]
                    parent_name = (parent_info.get('name') or '').lower()
                    
                    # Suspicious: cheat tool spawning legitimate processes
                    if any(cheat in parent_name for cheat in ['cheat', 'hack', 'inject', 'trainer']):
                        if proc_name in self.legitimate_processes:
                            violations.append(Violation(
                                component=self.name,
                                severity=ViolationSeverity.HIGH,
                                description=f"Suspicious process spawning: {parent_name} -> {proc_name}",
                                evidence={
                                    "parent_process": parent_name,
                                    "child_process": proc_name,
                                    "parent_pid": ppid,
                                    "child_pid": pid,
                                    "relationship_type": "cheat_spawning_legitimate"
                                }
                            ))
                
                # Check for processes with suspicious command lines
                cmdline = ' '.join(proc_info.get('cmdline') or []).lower()
                suspicious_cmdline_patterns = [
                    'inject', 'hook', 'patch', 'bypass', 'crack', 'cheat', 'hack',
                    'memory', 'process', 'dll', 'api', 'debug', 'attach', 'suspend'
                ]
                
                for pattern in suspicious_cmdline_patterns:
                    if pattern in cmdline and len(cmdline) > 20:  # Avoid false positives on short commands
                        violations.append(Violation(
                            component=self.name,
                            severity=ViolationSeverity.MEDIUM,
                            description=f"Suspicious command line detected: {proc_name}",
                            evidence={
                                "process_name": proc_name,
                                "process_pid": pid,
                                "command_line": cmdline,
                                "suspicious_pattern": pattern
                            }
                        ))
                        break
        
        except Exception as e:
            violations.append(Violation(
                component=self.name,
                severity=ViolationSeverity.LOW,
                description=f"Process relationship analysis error: {str(e)}",
                evidence={"error_type": type(e).__name__}
            ))
        
        return violations
    
    def analyze_process_characteristics(self, processes: List[ProcessInfo]) -> List[ProcessAnalysis]:
        """
        Analyze characteristics of processes for suspicious behavior.
        
        Args:
            processes: List of ProcessInfo objects to analyze
            
        Returns:
            List of ProcessAnalysis results
        """
        analysis_results = []
        
        for process in processes:
            if not isinstance(process, WindowsProcessInfo):
                continue
            
            risk_score = 0.0
            suspicious_indicators = []
            
            # Check if process is in legitimate whitelist
            name_lower = (process.name or '').lower()
            if name_lower in self.legitimate_processes:
                # Legitimate system process, lower risk
                risk_score = 0.0
            else:
                # EXTREME DETECTION: Multiple detection layers
                
                # Layer 1: Exact name matching (highest priority)
                for suspicious_name in self.suspicious_names:
                    if suspicious_name == name_lower:
                        risk_score += 0.8  # Very high risk for exact matches
                        suspicious_indicators.append(f"exact_name_match:{suspicious_name}")
                        break
                
                # Layer 2: Partial name matching (medium priority)
                for suspicious_name in self.suspicious_names:
                    if len(suspicious_name) > 4 and suspicious_name in name_lower:
                        risk_score += 0.4
                        suspicious_indicators.append(f"partial_name_match:{suspicious_name}")
                
                # Layer 3: Executable name analysis
                if process.executable_path:
                    exe_name = (process.executable_path.split('\\')[-1] if process.executable_path else '').lower()
                    if exe_name in self.suspicious_executables:
                        risk_score += 0.6
                        suspicious_indicators.append(f"suspicious_executable:{exe_name}")
                
                # Layer 4: Path analysis (multiple checks)
                if process.executable_path:
                    path_lower = (process.executable_path or '').lower()
                    
                    # Check for suspicious paths
                    for suspicious_path in self.suspicious_paths:
                        if suspicious_path in path_lower:
                            risk_score += 0.3
                            suspicious_indicators.append(f"suspicious_path:{suspicious_path}")
                    
                    # Check for system directory masquerading
                    if ("\\system32\\" in path_lower or "\\syswow64\\" in path_lower) and name_lower not in self.legitimate_processes:
                        risk_score += 0.5
                        suspicious_indicators.append("system_directory_masquerading")
                    
                    # Check for unsigned executables in system directories
                    if "\\windows\\" in path_lower and name_lower not in self.legitimate_processes:
                        risk_score += 0.4
                        suspicious_indicators.append("unsigned_system_executable")
                
                # Layer 5: Process behavior analysis
                if "elevated" in process.privileges and risk_score > 0:
                    risk_score += 0.2
                    suspicious_indicators.append("elevated_privileges_suspicious")
                
                # Layer 6: Process name pattern analysis
                proc_name = process.name or ''
                
                # Check for suspicious characters
                if any(char in proc_name for char in ['@', '#', '$', '%', '&', '*', '!', '?']):
                    risk_score += 0.15
                    suspicious_indicators.append("unusual_characters_in_name")
                
                # Check for very short or very long process names
                if len(proc_name) <= 2 or len(proc_name) >= 50:
                    risk_score += 0.1
                    suspicious_indicators.append("unusual_name_length")
                
                # Check for numeric-only names (suspicious)
                if proc_name.isdigit():
                    risk_score += 0.2
                    suspicious_indicators.append("numeric_only_name")
                
                # Check for random-looking names
                if len(proc_name) > 8 and not any(word in proc_name.lower() for word in ['windows', 'microsoft', 'system', 'service', 'update']):
                    vowels = sum(1 for c in proc_name.lower() if c in 'aeiou')
                    consonants = sum(1 for c in proc_name.lower() if c.isalpha() and c not in 'aeiou')
                    if vowels > 0 and consonants / vowels > 4:  # Too many consonants
                        risk_score += 0.1
                        suspicious_indicators.append("random_looking_name")
                
                # Layer 7: Multiple word analysis
                name_words = name_lower.replace('-', ' ').replace('_', ' ').split()
                cheat_words = ['cheat', 'hack', 'bot', 'mod', 'crack', 'trainer', 'auto', 'inject', 'hook', 'bypass', 'exploit']
                
                for word in name_words:
                    if word in cheat_words:
                        risk_score += 0.3
                        suspicious_indicators.append(f"cheat_word_detected:{word}")
                
                # Layer 8: File extension analysis (if available)
                if process.executable_path:
                    if not process.executable_path.lower().endswith('.exe'):
                        risk_score += 0.2
                        suspicious_indicators.append("non_exe_executable")
                
                # Layer 9: New process detection (post-baseline)
                if self.baseline_established and process.pid not in self.baseline_processes:
                    if risk_score > 0.2:  # Only flag if already suspicious
                        risk_score += 0.15
                        suspicious_indicators.append("new_suspicious_process")
                
                # Layer 10: Process clustering (multiple suspicious processes)
                if len(suspicious_indicators) >= 3:
                    risk_score += 0.1
                    suspicious_indicators.append("multiple_suspicious_indicators")
                
                # EXTREME: Immediate termination for critical threats
                if risk_score >= 0.9:
                    self._attempt_process_termination(process)
                    suspicious_indicators.append("auto_terminated_critical_threat")
            
            # Normalize risk score to 0-1 range
            risk_score = min(risk_score, 1.0)
            
            analysis = ProcessAnalysis(
                process_info=process,
                risk_score=risk_score,
                suspicious_indicators=suspicious_indicators
            )
            
            analysis_results.append(analysis)
        
        return analysis_results
    
    def detect_suspicious_processes(self, analysis: List[ProcessAnalysis]) -> List[Violation]:
        """
        Detect suspicious processes from analysis results.
        
        Args:
            analysis: List of ProcessAnalysis results
            
        Returns:
            List of detected violations
        """
        violations = []
        
        for proc_analysis in analysis:
            process = proc_analysis.process_info
            
            # Critical risk processes
            if proc_analysis.risk_score >= 0.8:
                violations.append(Violation(
                    component=self.name,
                    severity=ViolationSeverity.CRITICAL,
                    description=f"Critical-risk process detected: {process.name} (PID: {process.pid})",
                    evidence={
                        "process_name": process.name,
                        "process_pid": process.pid,
                        "executable_path": process.executable_path,
                        "risk_score": proc_analysis.risk_score,
                        "indicators": proc_analysis.suspicious_indicators,
                        "privileges": getattr(process, 'privileges', [])
                    }
                ))
            
            # High risk processes
            elif proc_analysis.risk_score >= 0.5:
                violations.append(Violation(
                    component=self.name,
                    severity=ViolationSeverity.HIGH,
                    description=f"High-risk process detected: {process.name} (PID: {process.pid})",
                    evidence={
                        "process_name": process.name,
                        "process_pid": process.pid,
                        "executable_path": process.executable_path,
                        "risk_score": proc_analysis.risk_score,
                        "indicators": proc_analysis.suspicious_indicators,
                        "privileges": getattr(process, 'privileges', [])
                    }
                ))
            
            # Medium risk processes
            elif proc_analysis.risk_score >= 0.3:
                violations.append(Violation(
                    component=self.name,
                    severity=ViolationSeverity.MEDIUM,
                    description=f"Suspicious process detected: {process.name} (PID: {process.pid})",
                    evidence={
                        "process_name": process.name,
                        "process_pid": process.pid,
                        "executable_path": process.executable_path,
                        "risk_score": proc_analysis.risk_score,
                        "indicators": proc_analysis.suspicious_indicators
                    }
                ))
            
            # Check for specific Windows injection attempts
            for indicator in proc_analysis.suspicious_indicators:
                if indicator == "system_directory_masquerading":
                    violations.append(Violation(
                        component=self.name,
                        severity=ViolationSeverity.HIGH,
                        description=f"Potential process masquerading in system directory: {process.name}",
                        evidence={
                            "process_name": process.name,
                            "process_pid": process.pid,
                            "executable_path": process.executable_path,
                            "category": "masquerading"
                        }
                    ))
                elif indicator == "no_executable_path":
                    violations.append(Violation(
                        component=self.name,
                        severity=ViolationSeverity.HIGH,
                        description=f"Process with no executable path (potential injection): {process.name}",
                        evidence={
                            "process_name": process.name,
                            "process_pid": process.pid,
                            "category": "injection_attempt"
                        }
                    ))
        
        return violations
    
    def get_violations(self) -> List[Violation]:
        """Get all detected violations."""
        return self.violations.copy()
    
    def get_process_count(self) -> int:
        """Get the current number of running processes."""
        try:
            return len(list(psutil.process_iter()))
        except Exception:
            return 0
    
    def get_baseline_info(self) -> Dict[str, Any]:
        """Get information about the process baseline."""
        return {
            "baseline_established": self.baseline_established,
            "baseline_process_count": len(self.baseline_processes),
            "current_process_count": self.get_process_count(),
            "monitoring_active": self.monitoring_thread is not None and self.monitoring_thread.is_alive(),
            "platform": "windows"
        }