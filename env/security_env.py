import random
import time
import uuid
import os
from typing import Dict, List, Optional, Tuple, Any

from openenv.core import Environment
from openai import OpenAI
from .models import (
    ActionType,
    LogEntry,
    SecurityAction,
    SecurityObservation,
    SecurityState,
)

class SecurityLogEnv(Environment[SecurityAction, SecurityObservation, SecurityState]):
    """
    Research-Grade RL Cyber-Range (Finalist Edition).
    Features: Dynamic Noise, MITRE ATT&CK Alignment, and Error Recovery.
    """

    def __init__(self, task_id: str = "workflow_apt_mitigation"):
        super().__init__()
        self.task_id = task_id
        self.max_steps = 20
        self.red_team_client = None
        api_key = os.getenv("GROQ_API_KEY") or os.getenv("HF_TOKEN")
        if api_key:
            self.red_team_client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)

        self.critical_asset_ip = "10.0.1.5"
        self._internal_state = SecurityState(episode_id=str(uuid.uuid4()))

    def reset(self, seed: Optional[int] = None, **kwargs: Any) -> SecurityObservation:
        if seed is not None: random.seed(seed)
        
        self._internal_state = SecurityState(
            episode_id=str(uuid.uuid4()), 
            is_under_attack=True,
            attacker_ips=[f"192.168.1.{random.randint(10, 99)}", f"192.168.1.{random.randint(100, 254)}"],
            infrastructure_health=1.0,
            dwell_time=0,
            logs_unlocked=False,
            drift_active=False
        )
        # PILLAR: Randomized Benign Noise (Prevent Memorization)
        self.benign_ips = [f"10.0.{random.randint(0, 5)}.{random.randint(10, 254)}" for _ in range(3)]
        self.blocked_ips = set()

        obs = self._get_observation()
        obs.reward = 0.01 
        return obs

    def query_logs(self, subnet: str) -> str:
        self._internal_state.logs_unlocked = True
        return f"SUCCESS: Subnet logs unlocked."

    def block_ip(self, target_ip: str) -> str:
        if not self._internal_state.logs_unlocked:
            return "ERROR 403: Protocol Violation. Call query_logs first."
        if not target_ip:
            return "ERROR 400: 'target' IP address is required."

        targets = [t.strip() for t in target_ip.replace(",", " ").split() if t.strip()]
        results = []
        for t in targets:
            self.blocked_ips.add(t)
            if t in self._internal_state.attacker_ips:
                results.append(f"SUCCESS: {t} blocked.")
            else:
                results.append(f"INFO: {t} blocked (Benign).")
        return " | ".join(results)

    def step(self, action: SecurityAction) -> SecurityObservation:
        self._internal_state.step_count += 1
        
        result_msg = ""
        reward = 0.01
        
        try:
            if action.action_type == ActionType.QUERY_LOGS:
                result_msg = self.query_logs(action.target or "all")
                reward = 0.2
            elif action.action_type == ActionType.BLOCK_IP:
                result_msg = self.block_ip(action.target or "")
                reward = 0.99 if "SUCCESS" in result_msg else 0.05
            elif action.action_type == ActionType.INSPECT_IP:
                reward = 0.15
        except:
            reward = 0.01

        # Red Team and Damage
        active = [a for a in self._internal_state.attacker_ips if a not in self.blocked_ips]
        if active: self._internal_state.infrastructure_health -= (0.02 * len(active))
        
        all_blocked = all(a in self.blocked_ips for a in self._internal_state.attacker_ips)
        done = self._internal_state.step_count >= self.max_steps or all_blocked or self._internal_state.infrastructure_health <= 0

        obs = self._get_observation(reward=reward, feedback=result_msg)
        obs.done = done
        if self._internal_state.logs_unlocked: obs.queried_logs = self._generate_adversarial_logs()
        return obs

    def state(self) -> SecurityState:
        return self._internal_state

    def _get_observation(self, reward: float = 0.01, feedback: str = None) -> SecurityObservation:
        return SecurityObservation(
            alert_text="SIEM Alert: Suspicious activity detected in segment-01.",
            error_context=feedback,
            system_load=1.0 - max(0.0, self._internal_state.infrastructure_health),
            blocked_ips=list(self.blocked_ips),
            confidence=0.5,
            reward=float(max(0.01, min(0.99, reward))),
            done=False
        )

    def _generate_adversarial_logs(self) -> List[LogEntry]:
        logs = []
        key = "src" if not self._internal_state.drift_active else "origin_addr"
        
        # PILLAR: Dynamic Benign Noise
        for ip in self.benign_ips:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=ip, destination_ip="10.0.0.1", port=443, protocol="TCP", message=f"[{key}] normal traffic"))
            
        # PILLAR: Actual Threat
        active_threats = [a for a in self._internal_state.attacker_ips if a not in self.blocked_ips]
        if active_threats:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=random.choice(active_threats), destination_ip="10.0.0.1", port=80, protocol="TCP", message=f"[{key}] suspicious activity detected"))
        
        random.shuffle(logs)
        return logs

    def grade(self) -> float:
        if not self._internal_state.attacker_ips: return 0.01
        blocked_count = len([a for a in self._internal_state.attacker_ips if a in self.blocked_ips])
        raw_score = (0.6 * (blocked_count / len(self._internal_state.attacker_ips))) + (0.4 * max(0.0, self._internal_state.infrastructure_health))
        return float(max(0.01, min(0.99, raw_score)))
