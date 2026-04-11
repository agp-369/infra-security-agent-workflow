import random
import time
from typing import Dict, List, Optional, Tuple, Any

from openenv.core import Environment
from ..models import (
    ActionType,
    LogEntry,
    SecurityAction,
    SecurityObservation,
    SecurityState,
)

class SecurityLogEnv(Environment[SecurityAction, SecurityObservation, SecurityState]):
    """
    Expert-Grade Infrastructure Security RL Environment.
    RESTORED: Full Adversarial Logic and Weighted Grading.
    """

    def __init__(self, task_id: str = "workflow_brute_force"):
        super().__init__()
        self.task_id = task_id
        self.max_steps = 20
        self.current_step = 0
        self.blocked_ips = set()
        self.health = 1.0
        self.attackers = [] 
        self.benign_user = f"10.0.2.{random.randint(100, 254)}"
        self.is_attack_active = False
        self.inspection_history = set()

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": "Infra Security Agent",
            "description": "High-fidelity security analyst simulation.",
            "version": "1.0.0",
            "tasks": [
                {"id": "workflow_brute_force", "difficulty": "easy"},
                {"id": "workflow_sql_injection", "difficulty": "medium"},
                {"id": "workflow_credential_stuffing", "difficulty": "medium"},
                {"id": "workflow_apt_mitigation", "difficulty": "hard"},
                {"id": "workflow_insider_threat", "difficulty": "hard"}
            ]
        }

    def reset(self, seed: Optional[int] = None, **kwargs: Any) -> SecurityObservation:
        if seed is not None: random.seed(seed)
        self.current_step = 0
        self.blocked_ips = set()
        self.is_attack_active = True
        self.health = 1.0
        self.inspection_history = set()
        
        if self.task_id == "workflow_credential_stuffing":
            self.attackers = [f"192.168.1.{random.randint(10, 99)}" for _ in range(3)]
        elif self.task_id == "workflow_insider_threat":
            self.attackers = [f"10.0.1.{random.randint(10, 99)}"]
        else:
            self.attackers = [f"192.168.1.{random.randint(100, 254)}"]

        obs = self._get_observation()
        obs.reward = 0.01 
        return obs

    def step(self, action: SecurityAction) -> SecurityObservation:
        self.current_step += 1
        inspections = []
        targets = [t.strip().strip(",") for t in str(action.target).replace(",", " ").split() if t.strip()] if action.target else []

        if action.action_type == ActionType.INSPECT_IP:
            for t in targets:
                self.inspection_history.add(t)
                if t in self.attackers: inspections.append(f"CRITICAL: {t} is MALICIOUS.")
                else: inspections.append(f"INFO: {t} is BENIGN.")

        if action.action_type == ActionType.BLOCK_IP:
            for t in targets: self.blocked_ips.add(t)

        if self.is_attack_active:
            active_threats = [a for a in self.attackers if a not in self.blocked_ips]
            if active_threats:
                damage = 0.015 * len(active_threats)
                if self.task_id == "workflow_brute_force": damage *= (1 + (self.current_step // 5))
                self.health -= damage
            else:
                self.is_attack_active = False 

        reward = self._calculate_reward(action, targets)
        obs = self._get_observation()
        obs.reward = float(max(0.01, min(0.99, reward)))
        obs.done = self.current_step >= self.max_steps or not self.is_attack_active or self.health <= 0
        obs.inspection_result = " | ".join(inspections) if inspections else None
        return obs

    @property
    def state(self) -> SecurityState:
        return SecurityState(episode_id="eval", step_count=self.current_step, is_under_attack=self.is_attack_active, infrastructure_health=max(0.0, self.health), attacker_ips=self.attackers)

    def _get_observation(self) -> SecurityObservation:
        new_logs = []
        for _ in range(25):
            rand = random.random()
            if rand < 0.15 and self.is_attack_active:
                source_ip = random.choice([a for a in self.attackers if a not in self.blocked_ips] or self.attackers)
                message = self._generate_log_msg()
            elif rand < 0.25:
                source_ip = self.benign_user
                message = "Failed login: user 'admin' (Forgot password)."
            else:
                source_ip = f"10.0.5.{random.randint(1, 255)}"
                message = "System Heartbeat: OK."

            new_logs.append(LogEntry(timestamp=str(time.time()), source_ip=source_ip, destination_ip="10.0.0.1", port=80, protocol="TCP", message=message))
        return SecurityObservation(new_logs=new_logs, blocked_ips=list(self.blocked_ips), system_load=1.0-max(0.0, self.health), metrics={"health": float(self.health)}, reward=0.01, done=False)

    def _generate_log_msg(self) -> str:
        if self.task_id == "workflow_brute_force": return "SSH_AUTH_FAIL: High frequency."
        if self.task_id == "workflow_sql_injection": return "SQL_UNION_DETECTED: /api/query."
        if self.task_id == "workflow_credential_stuffing": return "DISTRIBUTED_STUFFING_ATTEMPT."
        if self.task_id == "workflow_insider_threat": return "DATA_EXFILTRATION: Mass download."
        return "APT_PROBE_DETECTED."

    def _calculate_reward(self, action: SecurityAction, targets: List[str]) -> float:
        for t in targets:
            if action.action_type == ActionType.BLOCK_IP and t.startswith("10.0.") and t not in self.attackers:
                return 0.01 
        hit_count = len([t for t in targets if t in self.attackers])
        if action.action_type == ActionType.BLOCK_IP and hit_count > 0:
            return 0.99 * (hit_count / len(self.attackers))
        if action.action_type == ActionType.INSPECT_IP and hit_count > 0:
            return 0.2
        return 0.01

    def grade(self) -> float:
        """Restored weighted grade formula."""
        if not self.attackers: return 0.01
        blocked_count = len([a for a in self.attackers if a in self.blocked_ips])
        protection_score = blocked_count / len(self.attackers)
        false_positives = len([ip for ip in self.blocked_ips if ip not in self.attackers])
        fp_penalty = false_positives * 0.2
        raw_score = (0.6 * protection_score) + (0.4 * max(0.0, self.health)) - fp_penalty
        return float(max(0.01, min(0.99, raw_score)))
