"""
Core interfaces for BLACS components.

This module defines the abstract base classes and interfaces that all
BLACS components must implement to ensure consistent behavior and
enable proper integration.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from .data_models import (
    InputEvent, Violation, MonitoringData, LockstepValidation,
    ExecutionMetrics, CPUMetrics, MemoryRegion, MemoryAccess,
    SyscallEvent, ProcessInfo, TimingAnalysis, SyscallAnalysis,
    ProcessAnalysis, ThreatAssessment, ViolationReport
)


class BaseMonitor(ABC):
    """Base class for all monitoring components."""
    
    def __init__(self, name: str):
        """Initialize the base monitor with a name."""
        self.name = name
        self.enabled = True
        self.violations: List[Violation] = []
    
    @abstractmethod
    def start_monitoring(self) -> None:
        """Start the monitoring process."""
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop the monitoring process."""
        pass
    
    @abstractmethod
    def get_violations(self) -> List[Violation]:
        """Get all detected violations."""
        pass
    
    def enable(self) -> None:
        """Enable the monitor."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable the monitor."""
        self.enabled = False
    
    def clear_violations(self) -> None:
        """Clear all stored violations."""
        self.violations.clear()


class InputMonitorInterface(BaseMonitor):
    """Interface for input monitoring components."""
    
    @abstractmethod
    def capture_input_events(self) -> List[InputEvent]:
        """Capture and return input events."""
        pass
    
    @abstractmethod
    def analyze_timing_patterns(self, events: List[InputEvent]) -> TimingAnalysis:
        """Analyze timing patterns in input events."""
        pass
    
    @abstractmethod
    def detect_automation_patterns(self, analysis: TimingAnalysis) -> List[Violation]:
        """Detect automation patterns from timing analysis."""
        pass
    
    @abstractmethod
    def calculate_input_entropy(self, events: List[InputEvent]) -> float:
        """Calculate entropy of input events."""
        pass


class ExecutionMonitorInterface(BaseMonitor):
    """Interface for execution monitoring components."""
    
    @abstractmethod
    def measure_execution_timing(self) -> ExecutionMetrics:
        """Measure execution timing metrics."""
        pass
    
    @abstractmethod
    def track_cpu_usage(self) -> CPUMetrics:
        """Track CPU usage metrics."""
        pass
    
    @abstractmethod
    def validate_time_progress_correlation(self, metrics: ExecutionMetrics) -> List[Violation]:
        """Validate correlation between time and progress."""
        pass
    
    @abstractmethod
    def detect_speed_manipulation(self) -> List[Violation]:
        """Detect speed manipulation attempts."""
        pass


class MemoryMonitorInterface(BaseMonitor):
    """Interface for memory monitoring components."""
    
    @abstractmethod
    def hash_memory_regions(self, regions: List[MemoryRegion]) -> Dict[str, str]:
        """Generate hashes for memory regions."""
        pass
    
    @abstractmethod
    def detect_memory_modifications(self, baseline: Dict[str, str]) -> List[Violation]:
        """Detect unauthorized memory modifications."""
        pass
    
    @abstractmethod
    def monitor_memory_access_patterns(self) -> List[MemoryAccess]:
        """Monitor memory access patterns."""
        pass


class SyscallMonitorInterface(BaseMonitor):
    """Interface for system call monitoring components."""
    
    @abstractmethod
    def capture_syscalls(self) -> List[SyscallEvent]:
        """Capture system call events."""
        pass
    
    @abstractmethod
    def analyze_syscall_patterns(self, events: List[SyscallEvent]) -> SyscallAnalysis:
        """Analyze system call patterns."""
        pass
    
    @abstractmethod
    def detect_debugging_tools(self, analysis: SyscallAnalysis) -> List[Violation]:
        """Detect debugging tools from syscall patterns."""
        pass


class ProcessMonitorInterface(BaseMonitor):
    """Interface for process monitoring components."""
    
    @abstractmethod
    def enumerate_processes(self) -> List[ProcessInfo]:
        """Enumerate all running processes."""
        pass
    
    @abstractmethod
    def analyze_process_characteristics(self, processes: List[ProcessInfo]) -> List[ProcessAnalysis]:
        """Analyze characteristics of processes."""
        pass
    
    @abstractmethod
    def detect_suspicious_processes(self, analysis: List[ProcessAnalysis]) -> List[Violation]:
        """Detect suspicious processes from analysis."""
        pass


class RuleEngineInterface(ABC):
    """Interface for the rule engine component."""
    
    @abstractmethod
    def apply_lockstep_rules(self, monitoring_data: MonitoringData) -> List[Violation]:
        """Apply lockstep validation rules to monitoring data."""
        pass
    
    @abstractmethod
    def correlate_violations(self, violations: List[Violation]) -> ThreatAssessment:
        """Correlate violations to assess overall threat."""
        pass
    
    @abstractmethod
    def generate_violation_report(self, assessment: ThreatAssessment) -> ViolationReport:
        """Generate a comprehensive violation report."""
        pass


class LoggingInterface(ABC):
    """Interface for logging and reporting components."""
    
    @abstractmethod
    def log_violation(self, violation: Violation) -> None:
        """Log a single violation."""
        pass
    
    @abstractmethod
    def log_report(self, report: ViolationReport) -> None:
        """Log a violation report."""
        pass
    
    @abstractmethod
    def get_audit_trail(self, start_time: Optional[float] = None, 
                       end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Get audit trail entries within time range."""
        pass
    
    @abstractmethod
    def generate_summary_report(self, time_range: Optional[tuple] = None) -> Dict[str, Any]:
        """Generate a summary report of violations."""
        pass
    
    @abstractmethod
    def ensure_log_integrity(self) -> bool:
        """Ensure log integrity and prevent tampering."""
        pass