"""
Input Monitor component for BLACS.

This module implements input monitoring functionality to detect automated
input tools, unnatural input patterns, and timing manipulation.
"""

import time
import math
import statistics
from typing import List, Dict, Any, Optional
from collections import deque
import threading

from ..core.interfaces import InputMonitorInterface
from ..core.data_models import (
    InputEvent, Violation, TimingAnalysis, EventType, ViolationSeverity
)
from ..platform.detection import platform_detector


class InputMonitor(InputMonitorInterface):
    """Input monitoring component that detects automation and unnatural patterns."""
    
    def __init__(self, buffer_size: int = 1000, analysis_window: float = 10.0):
        """
        Initialize the input monitor.
        
        Args:
            buffer_size: Maximum number of events to keep in buffer
            analysis_window: Time window in seconds for analysis
        """
        super().__init__("InputMonitor")
        self.buffer_size = buffer_size
        self.analysis_window = analysis_window
        self.event_buffer: deque = deque(maxlen=buffer_size)
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Thresholds for violation detection
        self.max_human_frequency = 100.0  # clicks/second
        self.min_interval_variance = 0.1  # minimum variance for human input
        self.max_regularity_score = 0.98  # maximum regularity for human input
        self.automation_threshold = 0.9  # automation probability threshold
    
    def start_monitoring(self) -> None:
        """Start the input monitoring process."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.stop_event.clear()
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop the input monitoring process."""
        if self.monitoring_thread:
            self.stop_event.set()
            self.monitoring_thread.join(timeout=2.0)
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop for capturing input events."""
        while not self.stop_event.is_set():
            try:
                # In a real implementation, this would capture actual input events
                # For now, we'll simulate the monitoring process
                time.sleep(0.1)
            except Exception as e:
                # Log error and continue monitoring
                violation = Violation(
                    component=self.name,
                    severity=ViolationSeverity.LOW,
                    description=f"Input monitoring error: {str(e)}",
                    evidence={"error_type": type(e).__name__}
                )
                self.violations.append(violation)
    
    def capture_input_events(self) -> List[InputEvent]:
        """
        Capture and return recent input events.
        
        Returns:
            List of captured input events
        """
        # Return events from the current buffer
        current_time = time.time()
        recent_events = []
        
        for event in self.event_buffer:
            if current_time - event.timestamp <= self.analysis_window:
                recent_events.append(event)
        
        return recent_events
    
    def analyze_timing_patterns(self, events: List[InputEvent]) -> TimingAnalysis:
        """
        Analyze timing patterns in input events.
        
        Args:
            events: List of input events to analyze
            
        Returns:
            TimingAnalysis with statistical measurements
        """
        if len(events) < 2:
            return TimingAnalysis(
                mean_interval=0.0,
                std_deviation=0.0,
                entropy=0.0,
                regularity_score=0.0,
                automation_probability=0.0
            )
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Calculate intervals between events
        intervals = []
        for i in range(1, len(sorted_events)):
            interval = sorted_events[i].timestamp - sorted_events[i-1].timestamp
            intervals.append(interval)
        
        if not intervals:
            return TimingAnalysis(
                mean_interval=0.0,
                std_deviation=0.0,
                entropy=0.0,
                regularity_score=0.0,
                automation_probability=0.0
            )
        
        # Calculate statistical measures
        mean_interval = statistics.mean(intervals)
        std_deviation = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        
        # Calculate entropy (measure of randomness)
        entropy = self._calculate_entropy(intervals)
        
        # Calculate regularity score (inverse of coefficient of variation)
        regularity_score = self._calculate_regularity_score(mean_interval, std_deviation)
        
        # Calculate automation probability based on multiple factors
        automation_probability = self._calculate_automation_probability(
            mean_interval, std_deviation, entropy, regularity_score
        )
        
        return TimingAnalysis(
            mean_interval=mean_interval,
            std_deviation=std_deviation,
            entropy=entropy,
            regularity_score=regularity_score,
            automation_probability=automation_probability
        )
    
    def detect_automation_patterns(self, analysis: TimingAnalysis) -> List[Violation]:
        """
        Detect automation patterns from timing analysis.
        
        Args:
            analysis: TimingAnalysis results
            
        Returns:
            List of detected violations
        """
        violations = []
        
        # Check for high frequency (too fast for human)
        if analysis.mean_interval > 0:
            frequency = 1.0 / analysis.mean_interval
            if frequency > self.max_human_frequency:
                violations.append(Violation(
                    component=self.name,
                    severity=ViolationSeverity.HIGH,
                    description=f"Input frequency too high: {frequency:.2f} events/sec",
                    evidence={
                        "frequency": frequency,
                        "threshold": self.max_human_frequency,
                        "mean_interval": analysis.mean_interval
                    }
                ))
        
        # Check for unnaturally consistent timing
        if analysis.std_deviation < self.min_interval_variance and analysis.mean_interval > 0:
            violations.append(Violation(
                component=self.name,
                severity=ViolationSeverity.MEDIUM,
                description=f"Input timing too consistent: std_dev={analysis.std_deviation:.4f}",
                evidence={
                    "std_deviation": analysis.std_deviation,
                    "threshold": self.min_interval_variance,
                    "mean_interval": analysis.mean_interval
                }
            ))
        
        # Check for high regularity score
        if analysis.regularity_score > self.max_regularity_score:
            violations.append(Violation(
                component=self.name,
                severity=ViolationSeverity.MEDIUM,
                description=f"Input pattern too regular: score={analysis.regularity_score:.3f}",
                evidence={
                    "regularity_score": analysis.regularity_score,
                    "threshold": self.max_regularity_score
                }
            ))
        
        # Check for high automation probability
        if analysis.automation_probability > self.automation_threshold:
            violations.append(Violation(
                component=self.name,
                severity=ViolationSeverity.HIGH,
                description=f"High automation probability: {analysis.automation_probability:.3f}",
                evidence={
                    "automation_probability": analysis.automation_probability,
                    "threshold": self.automation_threshold,
                    "analysis": {
                        "mean_interval": analysis.mean_interval,
                        "std_deviation": analysis.std_deviation,
                        "entropy": analysis.entropy,
                        "regularity_score": analysis.regularity_score
                    }
                }
            ))
        
        return violations
    
    def calculate_input_entropy(self, events: List[InputEvent]) -> float:
        """
        Calculate entropy of input events.
        
        Args:
            events: List of input events
            
        Returns:
            Entropy value (0.0 to 1.0, higher = more random)
        """
        if len(events) < 2:
            return 0.0
        
        # Extract intervals
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        intervals = []
        for i in range(1, len(sorted_events)):
            interval = sorted_events[i].timestamp - sorted_events[i-1].timestamp
            intervals.append(interval)
        
        return self._calculate_entropy(intervals)
    
    def _calculate_entropy(self, intervals: List[float]) -> float:
        """Calculate Shannon entropy of interval distribution."""
        if not intervals:
            return 0.0
        
        # Discretize intervals into bins
        min_interval = min(intervals)
        max_interval = max(intervals)
        
        if max_interval == min_interval:
            return 0.0  # No variation = no entropy
        
        # Create 10 bins
        num_bins = min(10, len(intervals))
        bin_size = (max_interval - min_interval) / num_bins
        
        # Count occurrences in each bin
        bin_counts = [0] * num_bins
        for interval in intervals:
            bin_index = min(int((interval - min_interval) / bin_size), num_bins - 1)
            bin_counts[bin_index] += 1
        
        # Calculate entropy
        total_count = len(intervals)
        entropy = 0.0
        for count in bin_counts:
            if count > 0:
                probability = count / total_count
                entropy -= probability * math.log2(probability)
        
        # Normalize to 0-1 range
        max_entropy = math.log2(num_bins)
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _calculate_regularity_score(self, mean_interval: float, std_deviation: float) -> float:
        """Calculate regularity score (0.0 = irregular, 1.0 = perfectly regular)."""
        if mean_interval <= 0:
            return 0.0
        
        # Coefficient of variation (CV) = std_dev / mean
        cv = std_deviation / mean_interval
        
        # Convert to regularity score (inverse relationship)
        # High CV = low regularity, Low CV = high regularity
        regularity_score = 1.0 / (1.0 + cv)
        
        return min(regularity_score, 1.0)
    
    def _calculate_automation_probability(self, mean_interval: float, std_deviation: float,
                                        entropy: float, regularity_score: float) -> float:
        """Calculate probability that input is automated."""
        factors = []
        
        # Factor 1: High frequency indicates automation
        if mean_interval > 0:
            frequency = 1.0 / mean_interval
            frequency_factor = min(frequency / self.max_human_frequency, 1.0)
            factors.append(frequency_factor)
        
        # Factor 2: Low variance indicates automation
        variance_factor = 1.0 - min(std_deviation / 0.1, 1.0)  # Normalize by expected human variance
        factors.append(variance_factor)
        
        # Factor 3: Low entropy indicates automation
        entropy_factor = 1.0 - entropy
        factors.append(entropy_factor)
        
        # Factor 4: High regularity indicates automation
        factors.append(regularity_score)
        
        # Combine factors (weighted average)
        if factors:
            automation_probability = sum(factors) / len(factors)
            return min(automation_probability, 1.0)
        
        return 0.0
    
    def get_violations(self) -> List[Violation]:
        """Get all detected violations."""
        return self.violations.copy()
    
    def add_input_event(self, event: InputEvent) -> None:
        """
        Add an input event to the buffer for analysis.
        
        Args:
            event: InputEvent to add
        """
        self.event_buffer.append(event)
        
        # Perform real-time analysis if we have enough events
        if len(self.event_buffer) >= 10:
            recent_events = list(self.event_buffer)[-50:]  # Analyze last 50 events
            analysis = self.analyze_timing_patterns(recent_events)
            violations = self.detect_automation_patterns(analysis)
            self.violations.extend(violations)