"""
Core data models for the BLACS system.

This module defines all the data structures used throughout the BLACS system
for representing input events, violations, monitoring data, and analysis results.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
import time
import uuid


class ViolationSeverity(Enum):
    """Enumeration of violation severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(Enum):
    """Enumeration of input event types."""
    KEYBOARD = "keyboard"
    MOUSE = "mouse"


@dataclass
class InputEvent:
    """Represents a single user input event."""
    timestamp: float
    event_type: EventType
    details: Dict[str, Any]
    
    def __post_init__(self):
        """Validate the input event after initialization."""
        if self.timestamp <= 0:
            raise ValueError("Timestamp must be positive")
        if not isinstance(self.details, dict):
            raise ValueError("Details must be a dictionary")


@dataclass
class Violation:
    """Represents a detected violation in the system."""
    violation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    component: str = ""
    severity: ViolationSeverity = ViolationSeverity.LOW
    description: str = ""
    timestamp: float = field(default_factory=time.time)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate the violation after initialization."""
        if not self.component:
            raise ValueError("Component must be specified")
        if not self.description:
            raise ValueError("Description must be provided")


@dataclass
class ExecutionMetrics:
    """Metrics related to application execution timing and performance."""
    start_time: float
    end_time: float
    cpu_time: float
    wall_time: float
    progress_indicators: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> float:
        """Calculate the total execution duration."""
        return self.end_time - self.start_time
    
    def __post_init__(self):
        """Validate execution metrics after initialization."""
        if self.end_time < self.start_time:
            raise ValueError("End time must be after start time")
        if self.cpu_time < 0:
            raise ValueError("CPU time must be non-negative")


@dataclass
class CPUMetrics:
    """CPU usage metrics for monitoring execution patterns."""
    user_time: float
    system_time: float
    idle_time: float
    usage_percentage: float
    
    def __post_init__(self):
        """Validate CPU metrics after initialization."""
        if not (0 <= self.usage_percentage <= 100):
            raise ValueError("CPU usage percentage must be between 0 and 100")


@dataclass
class MemoryRegion:
    """Represents a memory region to be monitored."""
    start_address: int
    size: int
    permissions: str
    name: Optional[str] = None
    
    @property
    def end_address(self) -> int:
        """Calculate the end address of the memory region."""
        return self.start_address + self.size
    
    def __post_init__(self):
        """Validate memory region after initialization."""
        if self.size <= 0:
            raise ValueError("Memory region size must be positive")


@dataclass
class MemoryAccess:
    """Represents a memory access event."""
    timestamp: float
    address: int
    access_type: str  # 'read', 'write', 'execute'
    size: int
    process_id: int
    
    def __post_init__(self):
        """Validate memory access after initialization."""
        if self.access_type not in ['read', 'write', 'execute']:
            raise ValueError("Access type must be 'read', 'write', or 'execute'")
        if self.size <= 0:
            raise ValueError("Access size must be positive")


@dataclass
class SyscallEvent:
    """Represents a system call event."""
    timestamp: float
    syscall_name: str
    process_id: int
    arguments: List[Any] = field(default_factory=list)
    return_value: Optional[Any] = None
    duration: Optional[float] = None
    
    def __post_init__(self):
        """Validate syscall event after initialization."""
        if not self.syscall_name:
            raise ValueError("Syscall name must be provided")


@dataclass
class ProcessInfo:
    """Base class for process information."""
    pid: int
    name: str
    executable_path: str
    start_time: float
    
    def __post_init__(self):
        """Validate process info after initialization."""
        if self.pid <= 0:
            raise ValueError("Process ID must be positive")
        if not self.name:
            raise ValueError("Process name must be provided")


@dataclass
class LinuxProcessInfo(ProcessInfo):
    """Linux-specific process information."""
    cmdline: str = ""
    proc_status: Dict[str, str] = field(default_factory=dict)
    memory_maps: List[str] = field(default_factory=list)


@dataclass
class WindowsProcessInfo(ProcessInfo):
    """Windows-specific process information."""
    process_name: str = ""
    privileges: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate Windows process info after initialization."""
        super().__post_init__()
        if not self.process_name:
            self.process_name = self.name


@dataclass
class TimingAnalysis:
    """Analysis results for input timing patterns."""
    mean_interval: float
    std_deviation: float
    entropy: float
    regularity_score: float
    automation_probability: float
    
    def __post_init__(self):
        """Validate timing analysis after initialization."""
        if not (0 <= self.automation_probability <= 1):
            raise ValueError("Automation probability must be between 0 and 1")


@dataclass
class SyscallAnalysis:
    """Analysis results for system call patterns."""
    call_frequency: Dict[str, int] = field(default_factory=dict)
    timing_patterns: Dict[str, float] = field(default_factory=dict)
    suspicious_sequences: List[List[str]] = field(default_factory=list)
    automation_indicators: List[str] = field(default_factory=list)


@dataclass
class ProcessAnalysis:
    """Analysis results for process characteristics."""
    process_info: ProcessInfo
    risk_score: float
    suspicious_indicators: List[str] = field(default_factory=list)
    memory_access_patterns: List[MemoryAccess] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate process analysis after initialization."""
        if not (0 <= self.risk_score <= 1):
            raise ValueError("Risk score must be between 0 and 1")


@dataclass
class ThreatAssessment:
    """Overall threat assessment based on correlated violations."""
    threat_level: ViolationSeverity
    confidence: float
    correlated_violations: List[Violation] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate threat assessment after initialization."""
        if not (0 <= self.confidence <= 1):
            raise ValueError("Confidence must be between 0 and 1")


@dataclass
class ViolationReport:
    """Comprehensive report of detected violations."""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    threat_assessment: ThreatAssessment = field(default_factory=lambda: ThreatAssessment(
        threat_level=ViolationSeverity.LOW, confidence=0.0))
    violations: List[Violation] = field(default_factory=list)
    summary: str = ""
    
    def __post_init__(self):
        """Validate violation report after initialization."""
        if not self.summary and self.violations:
            self.summary = f"Report contains {len(self.violations)} violations"


@dataclass
class MonitoringData:
    """Aggregated monitoring data from all components."""
    timestamp: float = field(default_factory=time.time)
    input_events: List[InputEvent] = field(default_factory=list)
    execution_metrics: Optional[ExecutionMetrics] = None
    memory_state: Dict[str, str] = field(default_factory=dict)
    syscall_events: List[SyscallEvent] = field(default_factory=list)
    process_info: List[ProcessInfo] = field(default_factory=list)


@dataclass
class LockstepValidation:
    """Results of lockstep validation across different system layers."""
    input_execution_sync: bool = True
    time_progress_sync: bool = True
    memory_execution_sync: bool = True
    syscall_behavior_sync: bool = True
    validation_timestamp: float = field(default_factory=time.time)
    
    @property
    def is_valid(self) -> bool:
        """Check if all lockstep validations pass."""
        return all([
            self.input_execution_sync,
            self.time_progress_sync,
            self.memory_execution_sync,
            self.syscall_behavior_sync
        ])