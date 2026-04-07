from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from openenv.core import Action, Observation, State


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    INSPECT_IP = "inspect_ip"
    ALLOW = "allow"
    NOOP = "noop"


class LogEntry(BaseModel):
    timestamp: str
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    message: str
    status_code: Optional[int] = None


class SecurityAction(Action):
    action_type: ActionType
    target: Optional[str] = Field(None, description="The target IP or File.")
    reason: Optional[str] = Field(None, description="Reasoning for the action.")


class SecurityObservation(Observation):
    new_logs: List[LogEntry] = Field(default_factory=list)
    active_alerts: List[str] = Field(default_factory=list)
    system_load: float = 0.0
    blocked_ips: List[str] = Field(default_factory=list)
    quarantined_files: List[str] = Field(default_factory=list)
    inspection_result: Optional[str] = None


class SecurityState(State):
    is_under_attack: bool = False
    attack_phase: str = "Idle" # Recon, Access, Lateral, Exfil
    attacker_ips: List[str] = Field(default_factory=list)
    kill_chain_step: int = 0
    infrastructure_health: float = 1.0
    threat_level: str = "LOW"
