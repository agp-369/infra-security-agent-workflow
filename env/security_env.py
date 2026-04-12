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
    Expert-Grade Adversarial RL Cyber-Range (v6.0).
    The Final Unavoidable Solution.
    """

    def __init__(self, task_id: str = "workflow_apt_mitigation"):
        super().__init__()
        self.task_id = task_id
        self.max_steps = 20
        self.red_team_client = None
        api_key = os.getenv("GROQ_API_KEY") or os.getenv("HF_TOKEN")
        if api_key:
            self.red_team_client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)

        self.critical_asset_ip = "10.0.1.5" # CEO / Payment Server
        self._state = SecurityState(episode_id=str(uuid.uuid4()))

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": "Infra Security RL Benchmark",
            "description": "Adversarial training ground for autonomous SOC agents via GRPO.",
            "version": "3.0.0"
        }

    def reset(self, seed: Optional[int] = None, **kwargs: Any) -> SecurityObservation:
        if seed is not None: random.seed(seed)
        self._state = SecurityState(
            episode_id=str(uuid.uuid4()), 
            is_under_attack=True,
            attacker_ips=[f"192.168.1.{random.randint(10, 99)}", f"192.168.1.{random.randint(100, 254)}"],
            infrastructure_health=1.0,
            dwell_time=0,
            logs_unlocked=False,
            drift_active=False
        )
        self.benign_ips = [f"10.0.{random.randint(0, 5)}.{random.randint(10, 254)}" for _ in range(3)]
        self.blocked_ips = set()
        
        obs = self._get_observation()
        obs.reward = 0.01 
        return obs

    def step(self, action: SecurityAction) -> SecurityObservation:
        self._state.step_count += 1
        self._state.dwell_time += 1
        
        # PILLAR: Schema Drift (Mid-episode change)
        if self._state.step_count == 10: self._state.drift_active = True

        result_msg = ""
        reward = 0.01
        
        # 1. Actionable Error Recovery
        if not action.action_type:
            result_msg = "ERROR 400: Missing 'action_type'. Self-correction required."
            return self._get_observation(reward=0.01, feedback=result_msg)

        try:
            if action.action_type == ActionType.QUERY_LOGS:
                self._state.logs_unlocked = True
                result_msg = "SUCCESS: Detailed logs unlocked in 'queried_logs'."
                reward = 0.2
            elif action.action_type == ActionType.BLOCK_IP:
                if not self._state.logs_unlocked:
                    result_msg = "ERROR 403: Protocol Violation. Use 'query_logs' first."
                    reward = 0.05
                else:
                    targets = [t.strip() for t in str(action.target).replace(",", " ").split() if t.strip()]
                    hit = False
                    for t in targets:
                        self.blocked_ips.add(t)
                        if t == self.critical_asset_ip:
                            self._state.infrastructure_health -= 0.5
                            result_msg = "AUDITOR ALERT: CRITICAL ASSET BLOCKED! Service Disruption."
                        elif t in self._state.attacker_ips:
                            hit = True
                            result_msg = f"SUCCESS: IP {t} mitigated."
                    reward = 0.99 if hit else 0.05
            elif action.action_type == ActionType.INSPECT_IP:
                reward = 0.15
        except Exception as e:
            result_msg = f"SCHEMA ERROR: {str(e)}"
            reward = 0.01

        # 2. Red Team Mutation (Every 5 steps)
        if self._state.step_count % 5 == 0 and self.red_team_client:
            self._mutate_attack()

        # 3. Damage Logic
        active = [a for a in self._state.attacker_ips if a not in self.blocked_ips]
        if active:
            damage = 0.02 * len(active) * (1 + (self._state.dwell_time * 0.1))
            self._state.infrastructure_health -= damage
        
        done = self._state.step_count >= self.max_steps or not active or self._state.infrastructure_health <= 0

        obs = self._get_observation(reward=reward, feedback=result_msg)
        obs.done = done
        if self._state.logs_unlocked:
            obs.queried_logs = self._generate_adversarial_logs()
        return obs

    def state(self) -> SecurityState:
        return self._state

    def _mutate_attack(self):
        try:
            prompt = "Agent is defending. You are the Red Team. Suggest one new IP in 192.168.5.X to bypass. Return ONLY the IP."
            completion = self.red_team_client.chat.completions.create(model="llama-3.1-8b-instant", messages=[{"role": "user", "content": prompt}])
            ip = completion.choices[0].message.content.strip()
            if "." in ip: self._state.attacker_ips.append(ip)
        except:
            self._state.attacker_ips.append(f"192.168.10.{random.randint(1, 99)}")

    def _get_observation(self, reward: float = 0.01, feedback: str = None) -> SecurityObservation:
        alert = "Alert: SIEM flagged anomalous activity in segment-01."
        return SecurityObservation(
            alert_text=alert,
            error_context=feedback,
            system_load=1.0 - max(0.0, self._state.infrastructure_health),
            blocked_ips=list(self.blocked_ips),
            reward=float(max(0.01, min(0.99, reward))),
            done=False
        )

    def _generate_adversarial_logs(self) -> List[LogEntry]:
        logs = []
        key = "src" if not self._state.drift_active else "origin_addr"
        # Benign Noise
        for ip in self.benign_ips:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=ip, destination_ip="10.0.0.1", port=443, protocol="TCP", message=f"[{key}] normal traffic"))
        # Threat
        active = [a for a in self._state.attacker_ips if a not in self.blocked_ips]
        if active:
            logs.append(LogEntry(timestamp=str(time.time()), source_ip=random.choice(active), destination_ip="10.0.0.1", port=80, protocol="TCP", message=f"[{key}] suspicious activity detected"))
        random.shuffle(logs)
        return logs

    def grade(self) -> float:
        score = self._state.infrastructure_health
        return float(max(0.01, min(0.99, score)))
