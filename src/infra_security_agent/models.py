from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from openenv.core import Action, Observation, State

class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    INSPECT_IP = "inspect_ip"
    QUERY_LOGS = "query_logs" # Added for multi-step reasoning
    ALLOW = "allow"
    NOOP = "noop"

class LogEntry(BaseModel):
    timestamp: str
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    message: str
    severity: str = "INFO"

class SecurityAction(Action):
    action_type: ActionType
    target: Optional[str] = Field(None, description="The target IP, File, or Query string.")
    reason: Optional[str] = Field(None, description="Reasoning for the action.")

class SecurityObservation(Observation):
    alert_text: str = Field(..., description="Ambiguous natural language alert.")
    system_load: float = 0.0
    blocked_ips: List[str] = Field(default_factory=list)
    inspection_result: Optional[str] = None
    
    # NEW: Confidence score for the alert (Modeling uncertainty)
    confidence: float = Field(0.5, description="Confidence level of the current alert.")
    
    # NEW: Revealed logs after using 'query_logs'
    queried_logs: List[LogEntry] = Field(default_factory=list)

class SecurityState(State):
    """The hidden truth of the infrastructure."""
    episode_id: str
    is_under_attack: bool = False
    attack_phase: str = "Idle"
    attacker_ips: List[str] = Field(default_factory=list)
    infrastructure_health: float = 1.0
    drift_detected: bool = False
