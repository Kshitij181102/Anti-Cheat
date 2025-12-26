"""
Behavior Lockstep Anti-Cheat System (BLACS)

A novel, rule-based anti-cheating framework that detects cheating by enforcing 
synchronization (lockstep) between user input, application execution, memory state, 
system calls, and background processes.
"""

__version__ = "0.1.0"
__author__ = "BLACS Development Team"

from .core.data_models import (
    InputEvent,
    Violation,
    MonitoringData,
    LockstepValidation,
    ExecutionMetrics,
    CPUMetrics,
    MemoryRegion,
    MemoryAccess,
    SyscallEvent,
    ProcessInfo,
    TimingAnalysis,
    SyscallAnalysis,
    ProcessAnalysis,
    ThreatAssessment,
    ViolationReport
)

from .core.interfaces import (
    BaseMonitor,
    InputMonitorInterface,
    ExecutionMonitorInterface,
    MemoryMonitorInterface,
    SyscallMonitorInterface,
    ProcessMonitorInterface,
    RuleEngineInterface,
    LoggingInterface
)

from .platform.detection import PlatformDetector
from .blacs_system import BLACSSystem

__all__ = [
    'InputEvent', 'Violation', 'MonitoringData', 'LockstepValidation',
    'ExecutionMetrics', 'CPUMetrics', 'MemoryRegion', 'MemoryAccess',
    'SyscallEvent', 'ProcessInfo', 'TimingAnalysis', 'SyscallAnalysis',
    'ProcessAnalysis', 'ThreatAssessment', 'ViolationReport',
    'BaseMonitor', 'InputMonitorInterface', 'ExecutionMonitorInterface',
    'MemoryMonitorInterface', 'SyscallMonitorInterface', 'ProcessMonitorInterface',
    'RuleEngineInterface', 'LoggingInterface',
    'PlatformDetector', 'BLACSSystem'
]