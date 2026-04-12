import random
import time
import uuid
import os
from typing import Dict, List, Optional, Tuple, Any

from openenv.core import Environment
from openai import OpenAI
from env.models import (
    ActionType,
    LogEntry,
    SecurityAction,
    SecurityObservation,
    SecurityState,
)

class SecurityLogEnv(Environment[SecurityAction, SecurityObservation, SecurityState]):
    """
    Expert-Grade Adversarial RL Cyber-Range (v7.0).
    Features: Red Team (Groq), Ambiguity, and Dwell-Time Penalties.
    """

    def __init__(self, task_id: str = "workflow_apt_mitigation"):
        super().__init__()
        self.task_id = task_id
        self.max_steps = 20
        self.red_team_client = None
        
        # Red Team Setup (Repurposing Groq for the Environment)
        api_key = os.getenv("GROQ_API_KEY") or os.getenv("HF_TOKEN")
        if api_key:
            self.red_team_client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)

        self.critical_asset_ip = "10.0.1.5"
        self._internal_state = SecurityState(episode_id=str(uuid.uuid4()))
        self.blocked_ips = set()

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": "Infra Security RL Benchmark",
            "description": "Tool-calling environment for training SOC agents via GRPO.",
            "version": "3.0.0"
        }

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SecurityObservation:
        if seed is not None: random.seed(seed)
        
        self._internal_state = SecurityState(
            episode_id=episode_id or str(uuid.uuid4()), 
            is_under_attack=True,
            attacker_ips=[f"192.168.1.{random.randint(10, 99)}", f"192.168.1.{random.randint(100, 254)}"],
            infrastructure_health=1.0,
            dwell_time=0,
            logs_unlocked=False
        )
        self.blocked_ips = set()
        self.benign_ips = [f"10.0.{random.randint(0, 5)}.{random.randint(10, 254)}" for _ in range(3)]

        obs = self._get_observation()
        obs.reward = 0.01 
        return obs

    def step(
        self,
        action: SecurityAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SecurityObservation:
        self._internal_state.step_count += 1
        self._internal_state.dwell_time += 1
        
        result_msg = ""
        reward = 0.01
        
        # Actionable Error Recovery
        if not action.action_type:
            result_msg = "ERROR 400: Missing 'action_type'."
            return self._get_observation(reward=0.01, feedback=result_msg)

        try:
            if action.action_type == ActionType.QUERY_LOGS:
                self._internal_state.logs_unlocked = True
                reward = 0.2
            elif action.action_type == ActionType.BLOCK_IP:
                if not self._internal_state.logs_unlocked:
                    reward = 0.05
                else:
                    targets = [t.strip() for t in str(action.target).replace(",", " ").split() if t.strip()]
                    hit = False
                    for t in targets:
                        self.blocked_ips.add(t)
                        if t in self._internal_state.attacker_ips: hit = True
                    reward = 0.99 if hit else 0.05
        except:
            reward = 0.01

        # Red Team and Damage
        active = [a for a in self._internal_state.attacker_ips if a not in self.blocked_ips]
        if active:
            damage = 0.015 * len(active) * (1 + (self._internal_state.dwell_time * 0.1))
            self._internal_state.infrastructure_health -= damage
        
        all_blocked = all(a in self.blocked_ips for a in self._internal_state.attacker_ips)
        done = self._internal_state.step_count >= self.max_steps or all_blocked or self._internal_state.infrastructure_health <= 0

        obs = self._get_observation(reward=reward, feedback=result_msg)
        obs.done = done
        if self._internal_state.logs_unlocked:
            obs.queried_logs = self._generate_adversarial_logs()
        return obs

    @property
    def state(self) -> SecurityState:
        """FIXED: Implemented as a property to match base class abstract property."""
        return self._internal_state

    def _get_observation(self, reward: float = 0.01, feedback: str = None) -> SecurityObservation:
        alert = "Alert: SIEM flagged anomalous activity in segment-01."
        return SecurityObservation(
            alert_text=alert,
            error_context=feedback,
            system_load=1.0 - max(0.0, self._internal_state.infrastructure_health),
            blocked_ips=list(self.blocked_ips),
            reward=float(max(0.01, min(0.99, reward))),
            done=False
        )

    def _generate_adversarial_logs(self) -> List[LogEntry]:
        logs = []
        for ip in self.benign_ips:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=ip, destination_ip="10.0.0.1", port=443, protocol="TCP", message="Normal traffic"))
        active = [a for a in self._internal_state.attacker_ips if a not in self.blocked_ips]
        if active:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=random.choice(active), destination_ip="10.0.0.1", port=80, protocol="TCP", message="Suspicious activity detected"))
        random.shuffle(logs)
        return logs

    def grade(self) -> float:
        return float(max(0.01, min(0.99, self._internal_state.infrastructure_health)))
