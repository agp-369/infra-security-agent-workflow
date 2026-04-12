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
            "tasks": [
                {"id": "workflow_brute_force", "difficulty": "easy", "has_grader": True},
                {"id": "workflow_sql_injection", "difficulty": "medium", "has_grader": True},
                {"id": "workflow_credential_stuffing", "difficulty": "medium", "has_grader": True},
                {"id": "workflow_apt_mitigation", "difficulty": "hard", "has_grader": True},
                {"id": "workflow_insider_threat", "difficulty": "hard", "has_grader": True}
            ],
            "version": "3.0.0"
        }

    def reset(self, seed: Optional[int] = None, episode_id: Optional[str] = None, **kwargs: Any) -> SecurityObservation:
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

    def query_logs(self, subnet: str) -> str:
        """Reveals detailed logs. Args: subnet."""
        self._internal_state.logs_unlocked = True
        return f"SUCCESS: Logs for {subnet} unlocked."

    def block_ip(self, target_ip: str) -> str:
        """Blocks traffic from IP. Args: target_ip."""
        if not self._internal_state.logs_unlocked:
            return "ERROR 403: Protocol Violation. Call query_logs first."
        
        if not target_ip:
            return "ERROR 400: Missing required field: target_ip."

        targets = [t.strip() for t in target_ip.replace(",", " ").split() if t.strip()]
        results = []
        for t in targets:
            self.blocked_ips.add(t)
            if t == self.critical_asset_ip:
                self._internal_state.infrastructure_health -= 0.4
                results.append(f"CRITICAL ERROR: IP {t} is a BUSINESS ASSET.")
            elif t in self._internal_state.attacker_ips:
                results.append(f"SUCCESS: IP {t} mitigated.")
            else:
                results.append(f"WARNING: IP {t} is benign.")
        
        return " | ".join(results)

    def step(self, action: SecurityAction, timeout_s: Optional[float] = None, **kwargs: Any) -> SecurityObservation:
        self._internal_state.step_count += 1
        self._internal_state.dwell_time += 1
        
        result_msg = ""
        reward = 0.01
        
        # 1. Actionable Error Recovery
        if not action.action_type:
            result_msg = "ERROR 400: Missing 'action_type'."
            return self._get_observation(reward=0.01, feedback=result_msg)

        try:
            if action.action_type == ActionType.QUERY_LOGS:
                result_msg = self.query_logs(action.target or "all")
                reward = 0.2
            elif action.action_type == ActionType.BLOCK_IP:
                result_msg = self.block_ip(action.target or "")
                reward = 0.99 if "SUCCESS" in result_msg else 0.05
            elif action.action_type == ActionType.INSPECT_IP:
                reward = 0.15
        except Exception as e:
            result_msg = f"ERROR 500: {str(e)}"

        # 2. Red Team Mutation
        if self._internal_state.step_count % 5 == 0 and self.red_team_client:
            self._mutate_attack()

        # 3. Dwell Time Damage
        active = [a for a in self._internal_state.attacker_ips if a not in self.blocked_ips]
        if active:
            damage = 0.015 * len(active) * (1 + (self._internal_state.dwell_time * 0.1))
            self._internal_state.infrastructure_health -= damage
        
        # 4. Result Assembly
        all_blocked = all(a in self.blocked_ips for a in self._internal_state.attacker_ips)
        done = self._internal_state.step_count >= self.max_steps or all_blocked or self._internal_state.infrastructure_health <= 0

        obs = self._get_observation(reward=reward, feedback=result_msg)
        obs.done = done
        if self._internal_state.logs_unlocked:
            obs.queried_logs = self._generate_adversarial_logs()
        return obs

    def state(self) -> SecurityState:
        return self._internal_state

    def _mutate_attack(self):
        try:
            prompt = "Suggest one new IP like 192.168.10.X to attack from. Return ONLY the IP."
            completion = self.red_team_client.chat.completions.create(model="llama-3.1-8b-instant", messages=[{"role": "user", "content": prompt}])
            ip = completion.choices[0].message.content.strip()
            if "." in ip: self._internal_state.attacker_ips.append(ip)
        except:
            self._internal_state.attacker_ips.append(f"192.168.10.{random.randint(1, 99)}")

    def _get_observation(self, reward: float = 0.01, feedback: str = None) -> SecurityObservation:
        # PILLAR: Natural Language Ambiguity
        alert = "Alert: SIEM flagged anomalous activity in segment-01."
        return SecurityObservation(
            alert_text=alert,
            error_context=feedback,
            system_load=1.0 - max(0.0, self._internal_state.infrastructure_health),
            blocked_ips=list(self.blocked_ips),
            metrics={"health": float(self._internal_state.infrastructure_health), "dwell": float(self._internal_state.dwell_time)},
            reward=float(max(0.01, min(0.99, reward))),
            done=False
        )

    def _generate_adversarial_logs(self) -> List[LogEntry]:
        logs = []
        # Benign Noise
        for ip in self.benign_ips:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=ip, destination_ip="10.0.0.1", port=443, protocol="TCP", message="Normal traffic"))
        # Actual Threat
        active = [a for a in self._internal_state.attacker_ips if a not in self.blocked_ips]
        if active:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=random.choice(active), destination_ip="10.0.0.1", port=80, protocol="TCP", message="Suspicious activity detected"))
        random.shuffle(logs)
        return logs

    def grade(self) -> float:
        return float(max(0.01, min(0.99, self._internal_state.infrastructure_health)))
