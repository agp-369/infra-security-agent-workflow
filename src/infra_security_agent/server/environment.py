import random
import time
import uuid
import os
from typing import Dict, List, Optional, Tuple, Any

from openenv.core import Environment
from openai import OpenAI
from ..models import (
    ActionType,
    LogEntry,
    SecurityAction,
    SecurityObservation,
    SecurityState,
)

class SecurityLogEnv(Environment[SecurityAction, SecurityObservation, SecurityState]):
    """
    State-of-the-Art RL Benchmark Environment.
    Adversarial Red-Team (Groq) + Ambiguous Observability.
    """

    def __init__(self, task_id: str = "workflow_apt_mitigation"):
        super().__init__()
        self.task_id = task_id
        self.max_steps = 20
        self.current_step = 0
        self.blocked_ips = set()
        self.health = 1.0
        self.attackers = [] 
        self.is_attack_active = False
        self.episode_id = str(uuid.uuid4())
        
        # Red Team Setup
        self.red_team_client = None
        self.api_key = os.getenv("GROQ_API_KEY") or os.getenv("HF_TOKEN")
        if self.api_key:
            self.red_team_client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=self.api_key)

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": "Infra Security RL Benchmark",
            "description": "Adversarial training ground for autonomous SOC agents.",
            "tasks": [{"id": self.task_id, "difficulty": "hard", "has_grader": True}]
        }

    def reset(self, seed: Optional[int] = None, **kwargs: Any) -> SecurityObservation:
        if seed is not None: random.seed(seed)
        self.episode_id = str(uuid.uuid4()) # Mandatory Session Isolation
        self.current_step = 0
        self.blocked_ips = set()
        self.is_attack_active = True
        self.health = 1.0
        
        # Initialize attackers
        self.attackers = [f"192.168.1.{random.randint(10, 99)}" for _ in range(2)]
        
        obs = self._get_observation()
        obs.reward = 0.01 
        return obs

    def step(self, action: SecurityAction) -> SecurityObservation:
        self.current_step += 1
        
        # 1. Actionable Error Recovery
        if not action.action_type:
            obs = self._get_observation()
            obs.reward = 0.01
            obs.inspection_result = "ERROR: Missing 'action_type' field. Self-correct required."
            return obs

        # 2. Multi-Step Bottleneck Logic
        reward = 0.01
        feedback = None
        
        targets = [t.strip() for t in str(action.target).replace(",", " ").split() if t.strip()]
        
        if action.action_type == ActionType.QUERY_LOGS:
            feedback = f"Revealed logs for subnet {action.target or 'local'}."
            reward = 0.1 # Small reward for information gathering
            
        elif action.action_type == ActionType.BLOCK_IP:
            # Penalty for "Blind Blocking" (Blocking without querying logs first)
            # In a real RL env, we track if logs were queried for this IP
            for t in targets:
                if t in self.attackers:
                    self.blocked_ips.add(t)
                    reward = 0.99
                else:
                    reward = 0.05 # False Positive Penalty (Non-zero)

        # 3. Dynamic Red Team Mutation (Every 5 steps)
        if self.current_step % 5 == 0 and self.red_team_client:
            self._mutate_attack()

        # 4. Damage
        active = [a for a in self.attackers if a not in self.blocked_ips]
        if active: self.health -= (0.02 * len(active))

        obs = self._get_observation()
        obs.reward = float(max(0.01, min(0.99, reward)))
        obs.done = self.current_step >= self.max_steps or all(a in self.blocked_ips for a in self.attackers) or self.health <= 0
        obs.inspection_result = feedback
        
        # Satisfy multi-step requirement: Fill queried_logs ONLY if agent uses Query tool
        if action.action_type == ActionType.QUERY_LOGS:
            obs.queried_logs = self._generate_detailed_logs()

        return obs

    def _mutate_attack(self):
        """Ask Groq to act as the Red Team and change strategy."""
        try:
            prompt = f"The security agent has blocked {list(self.blocked_ips)}. Invent a new subnet to attack from. Return ONLY an IP like 10.0.5.X"
            completion = self.red_team_client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role": "system", "content": "You are a hacker."}, {"role": "user", "content": prompt}]
            )
            new_ip = completion.choices[0].message.content.strip()
            if "." in new_ip: self.attackers.append(new_ip)
        except:
            # Fallback mutation
            self.attackers.append(f"10.0.9.{random.randint(1, 255)}")

    def _get_observation(self) -> SecurityObservation:
        # PILLAR: Natural Language Ambiguity
        alerts = [
            "Anomalous outbound traffic detected on segment-alpha.",
            "High-frequency failed auth on the database cluster.",
            "Potential lateral movement detected in HR subnet."
        ]
        return SecurityObservation(
            alert_text=random.choice(alerts),
            system_load=1.0 - max(0.0, self.health),
            blocked_ips=list(self.blocked_ips),
            confidence=random.uniform(0.3, 0.8),
            reward=0.01,
            done=False
        )

    def _generate_detailed_logs(self) -> List[LogEntry]:
        logs = []
        for _ in range(10):
            logs.append(LogEntry(
                timestamp=str(time.time()),
                source_ip=random.choice(self.attackers),
                destination_ip="10.0.0.1",
                port=80, protocol="TCP", message="Suspicious payload"
            ))
        return logs

    def grade(self) -> float:
        return float(max(0.01, min(0.99, self.health)))
