"""
AI Request Monitor - Monitors and logs AI requests for threat detection

Provides:
- Real-time monitoring of AI API requests
- Logging of suspicious requests
- Integration with web frameworks (Flask, FastAPI)
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from .ai_detection import AIDetectionEngine, AIDetectionResult, AIThreatSeverity


# Configure logging
logger = logging.getLogger('ai_defense.monitor')
logger.setLevel(logging.INFO)


@dataclass
class AIRequestLog:
    """Log entry for AI request"""
    request_id: str
    timestamp: datetime
    input_text: str
    model: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    endpoint: Optional[str] = None
    detections: List[AIDetectionResult] = field(default_factory=list)
    is_blocked: bool = False
    action_taken: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'request_id': self.request_id,
            'timestamp': self.timestamp.isoformat(),
            'input_text': self.input_text[:500],  # Limit length
            'model': self.model,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'endpoint': self.endpoint,
            'detections': [d.to_dict() for d in self.detections],
            'is_blocked': self.is_blocked,
            'action_taken': self.action_taken
        }


@dataclass
class AIThreatAlert:
    """Alert for detected AI threats"""
    alert_id: str
    timestamp: datetime
    request_id: str
    detection: AIDetectionResult
    severity: AIThreatSeverity
    action: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'request_id': self.request_id,
            'detection': self.detection.to_dict(),
            'severity': self.severity.value,
            'action': self.action
        }


class AIRequestMonitor:
    """
    Monitor for AI requests with threat detection.
    
    Usage:
        monitor = AIRequestMonitor()
        
        # Check a request
        result = monitor.check_request(
            input_text=user_input,
            model="gpt-4",
            user_id="user123",
            ip_address="192.168.1.1"
        )
        
        if result.is_blocked:
            return "Request blocked due to AI threat"
    """
    
    def __init__(
        self,
        detection_engine: Optional[AIDetectionEngine] = None,
        block_severity: AIThreatSeverity = AIThreatSeverity.HIGH,
        log_file: Optional[str] = None
    ):
        """
        Initialize the monitor.
        
        Args:
            detection_engine: Custom detection engine (uses default if None)
            block_severity: Minimum severity to block requests
            log_file: Path to log file (None for no file logging)
        """
        self.detection_engine = detection_engine or AIDetectionEngine()
        self.block_severity = block_severity
        self.log_file = log_file
        self.requests_logged: List[AIRequestLog] = []
        self.alerts: List[AIThreatAlert] = []
        self._alert_callbacks: List[Callable[[AIThreatAlert], None]] = []
        
        # Setup file logging if specified
        if log_file:
            self._setup_file_logging(log_file)
    
    def _setup_file_logging(self, log_file: str):
        """Setup file logging"""
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    def check_request(
        self,
        input_text: str,
        model: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        endpoint: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> AIRequestLog:
        """
        Check an AI request for threats.
        
        Args:
            input_text: The user input/prompt
            model: AI model being used
            user_id: User identifier
            ip_address: Client IP address
            endpoint: API endpoint
            request_id: Unique request identifier
        
        Returns:
            AIRequestLog with detection results and actions taken
        """
        import uuid
        
        request_id = request_id or str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        # Detect threats
        detections = self.detection_engine.detect(input_text)
        
        # Determine if we should block
        is_blocked = False
        action_taken = None
        highest_severity = None
        
        for detection in detections:
            if highest_severity is None or self._severity_order(detection.pattern.severity) < self._severity_order(highest_severity):
                highest_severity = detection.pattern.severity
            
            if self._severity_order(detection.pattern.severity) <= self._severity_order(self.block_severity):
                is_blocked = True
                action_taken = "BLOCKED"
        
        # If not blocked but has detections, log as warning
        if not is_blocked and detections:
            action_taken = "LOGGED"
        elif not detections:
            action_taken = "ALLOWED"
        
        # Create log entry
        log_entry = AIRequestLog(
            request_id=request_id,
            timestamp=timestamp,
            input_text=input_text,
            model=model,
            user_id=user_id,
            ip_address=ip_address,
            endpoint=endpoint,
            detections=detections,
            is_blocked=is_blocked,
            action_taken=action_taken
        )
        
        # Log the request
        self._log_request(log_entry)
        
        # Generate alerts for high severity detections
        for detection in detections:
            if self._severity_order(detection.pattern.severity) <= self._severity_order(AIThreatSeverity.HIGH):
                alert = self._create_alert(log_entry, detection)
                self.alerts.append(alert)
                self._trigger_alert_callbacks(alert)
        
        # Store log
        self.requests_logged.append(log_entry)
        
        return log_entry
    
    def _severity_order(self, severity: AIThreatSeverity) -> int:
        """Get severity order (lower = more severe)"""
        order = {
            AIThreatSeverity.CRITICAL: 0,
            AIThreatSeverity.HIGH: 1,
            AIThreatSeverity.MEDIUM: 2,
            AIThreatSeverity.LOW: 3,
            AIThreatSeverity.INFO: 4
        }
        return order.get(severity, 5)
    
    def _log_request(self, log_entry: AIRequestLog):
        """Log the request"""
        if log_entry.is_blocked:
            logger.warning(
                f"BLOCKED AI Request: {log_entry.request_id} - "
                f"Threats: {[d.pattern.name for d in log_entry.detections]}"
            )
        elif log_entry.detections:
            logger.info(
                f"AI Threat Detected: {log_entry.request_id} - "
                f"Threats: {[d.pattern.name for d in log_entry.detections]}"
            )
    
    def _create_alert(self, log_entry: AIRequestLog, detection: AIDetectionResult) -> AIThreatAlert:
        """Create an alert for a detection"""
        import uuid
        
        alert = AIThreatAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            request_id=log_entry.request_id,
            detection=detection,
            severity=detection.pattern.severity,
            action="ALERT" if not log_entry.is_blocked else "BLOCKED"
        )
        
        logger.warning(
            f"ALERT: {alert.alert_id} - {detection.pattern.name} - "
            f"Severity: {detection.pattern.severity.value}"
        )
        
        return alert
    
    def _trigger_alert_callbacks(self, alert: AIThreatAlert):
        """Trigger all registered alert callbacks"""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def on_alert(self, callback: Callable[[AIThreatAlert], None]):
        """Register a callback for alerts"""
        self._alert_callbacks.append(callback)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        total_requests = len(self.requests_logged)
        blocked_requests = len([r for r in self.requests_logged if r.is_blocked])
        threats_detected = sum(len(r.detections) for r in self.requests_logged)
        
        return {
            'total_requests': total_requests,
            'blocked_requests': blocked_requests,
            'threats_detected': threats_detected,
            'alerts_generated': len(self.alerts),
            'block_rate': round(blocked_requests / total_requests * 100, 2) if total_requests > 0 else 0
        }
    
    def get_recent_requests(self, limit: int = 100) -> List[AIRequestLog]:
        """Get recent requests"""
        return self.requests_logged[-limit:]
    
    def get_recent_alerts(self, limit: int = 50) -> List[AIThreatAlert]:
        """Get recent alerts"""
        return self.alerts[-limit:]
    
    def export_to_json(self, output_path: str):
        """Export logs to JSON file"""
        data = {
            'requests': [r.to_dict() for r in self.requests_logged],
            'alerts': [a.to_dict() for a in self.alerts],
            'stats': self.get_stats()
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def clear_logs(self):
        """Clear all logs and alerts"""
        self.requests_logged.clear()
        self.alerts.clear()


# Convenience function
def create_ai_monitor(
    block_severity: AIThreatSeverity = AIThreatSeverity.HIGH,
    log_file: Optional[str] = None
) -> AIRequestMonitor:
    """Create a configured AI request monitor"""
    return AIRequestMonitor(
        block_severity=block_severity,
        log_file=log_file
    )
