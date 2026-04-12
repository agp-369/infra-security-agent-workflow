import uuid
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from openenv.core import Action, Observation, State

class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    INSPECT_IP = "inspect_ip"
    QUERY_LOGS = "query_logs" # Essential for Multi-Step Reasoning
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
    reason: Optional[str] = Field(None, description="Detailed justification for the action.")

class SecurityObservation(Observation):
    # NATURAL LANGUAGE AMBIGUITY: The primary signal
    alert_text: str = Field(..., description="Ambiguous natural language alert from SIEM.")
    
    # ACTIONABLE ERROR RECOVERY: Specific hints for the agent
    error_context: Optional[str] = Field(None, description="Feedback for malformed or unauthorized actions.")
    
    # SYSTEM STATE
    system_load: float = 0.0
    blocked_ips: List[str] = Field(default_factory=list)
    inspection_result: Optional[str] = None
    
    # REVEALED DATA (Only populated after QUERY_LOGS)
    queried_logs: List[LogEntry] = Field(default_factory=list)

class SecurityState(State):
    """The 'Hidden Truth' - Never visible to the agent."""
    episode_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    is_under_attack: bool = False
    attacker_ips: List[str] = Field(default_factory=list)
    infrastructure_health: float = 1.0
    dwell_time: int = 0
    logs_unlocked: bool = False
    drift_active: bool = False
