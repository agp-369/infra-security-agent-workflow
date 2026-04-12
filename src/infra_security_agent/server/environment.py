import random
import time
import uuid
import os
from typing import Dict, List, Optional, Tuple, Any

from openenv.core import Environment
from openenv.core.env_server.types import EnvironmentMetadata
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
    Expert-Grade Adversarial RL Cyber-Range.
    Fully compliant with the official Meta Environment base class.
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
        self.blocked_ips = set()

    def get_metadata(self) -> EnvironmentMetadata:
        """Returns the official EnvironmentMetadata object."""
        return EnvironmentMetadata(
            name="Infra Security Agent",
            description="Tool-calling environment for training SOC agents.",
            version="3.0.0",
            author="Abhishek"
        )

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SecurityObservation:
        """Official Reset signature compliance."""
        if seed is not None:
            random.seed(seed)
            
        self._internal_state = SecurityState(
            episode_id=episode_id or str(uuid.uuid4()), 
            is_under_attack=True,
            attacker_ips=[f"192.168.1.{random.randint(10, 99)}", f"192.168.1.{random.randint(100, 254)}"],
            infrastructure_health=1.0,
            dwell_time=0,
            logs_unlocked=False,
            drift_active=False
        )
        self.blocked_ips = set()
        
        obs = self._get_observation()
        obs.reward = 0.01 
        return obs

    def step(
        self,
        action: SecurityAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SecurityObservation:
        """Official Step signature compliance."""
        self._internal_state.step_count += 1
        self._internal_state.dwell_time += 1
        
        result_msg = ""
        reward = 0.01
        
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
            self._internal_state.infrastructure_health -= (0.02 * len(active))
        
        done = self._internal_state.step_count >= self.max_steps or not active or self._internal_state.infrastructure_health <= 0

        obs = self._get_observation(reward=reward, feedback=result_msg)
        obs.done = done
        if self._internal_state.logs_unlocked:
            obs.queried_logs = self._generate_adversarial_logs()
        return obs

    @property
    def state(self) -> SecurityState:
        """FIXED: Property decorator matches abstract base class requirement."""
        return self._internal_state

    def _get_observation(self, reward: float = 0.01, feedback: str = None) -> SecurityObservation:
        return SecurityObservation(
            alert_text="Alert: SIEM anomaly detected.",
            error_context=feedback,
            system_load=1.0 - max(0.0, self._internal_state.infrastructure_health),
            blocked_ips=list(self.blocked_ips),
            reward=float(max(0.01, min(0.99, reward))),
            done=False
        )

    def _generate_adversarial_logs(self) -> List[LogEntry]:
        logs = []
        for _ in range(5):
            logs.append(LogEntry(
                timestamp=str(time.time()),
                source_ip=random.choice(self._internal_state.attacker_ips) if self._internal_state.attacker_ips else "127.0.0.1",
                destination_ip="10.0.0.1",
                port=80, protocol="TCP", message="Suspicious activity"
            ))
        return logs

    def grade(self) -> float:
        return float(max(0.01, min(0.99, self._internal_state.infrastructure_health)))
