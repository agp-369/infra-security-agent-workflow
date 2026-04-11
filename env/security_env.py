import random
import time
from typing import Dict, List, Optional, Tuple, Any

from openenv.core import Environment
from env.models import (
    ActionType,
    LogEntry,
    SecurityAction,
    SecurityObservation,
    SecurityState,
)

class SecurityLogEnv(Environment[SecurityAction, SecurityObservation, SecurityState]):
    """
    Expert-Grade Infrastructure Security RL Environment (v5.0).
    Benchmark Edition: MITRE ATT&CK Mapping & Dwell-Time Penalties.
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
        
        # PILLAR 1: MITRE ATT&CK Mapping
        self.mitre_map = {
            "workflow_brute_force": "T1110 (Credential Access)",
            "workflow_sql_injection": "T1190 (Exploit Public-Facing Application)",
            "workflow_credential_stuffing": "T1110.004 (Credential Stuffing)",
            "workflow_apt_mitigation": "TA0008 (Lateral Movement)",
            "workflow_insider_threat": "TA0010 (Exfiltration)"
        }
        
        self.dwell_time = 0
        self.investigation_count = 0

    def reset(self, seed: Optional[int] = None, **kwargs: Any) -> SecurityObservation:
        if seed is not None: random.seed(seed)
        self.current_step = 0
        self.dwell_time = 0
        self.investigation_count = 0
        self.blocked_ips = set()
        self.is_attack_active = True
        self.health = 1.0
        
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

        # PILLAR 3: Investigation Cost
        if action.action_type == ActionType.INSPECT_IP:
            self.investigation_count += 1
            for t in targets:
                if t in self.attackers: inspections.append(f"MITRE {self.mitre_map[self.task_id]}: MALICIOUS.")
                else: inspections.append(f"CLEAN: {t} is BENIGN.")

        if action.action_type == ActionType.BLOCK_IP:
            for t in targets: self.blocked_ips.add(t)

        # PILLAR 2: Dwell Time Logic
        if self.is_attack_active:
            active_threats = [a for a in self.attackers if a not in self.blocked_ips]
            if active_threats:
                self.dwell_time += 1
                # Non-linear damage: Gets more dangerous over time
                damage = 0.015 * len(active_threats) * (1 + (self.dwell_time * 0.1))
                self.health -= damage
            else:
                self.is_attack_active = False 

        reward = self._calculate_reward(action, targets)
        done = self.current_step >= self.max_steps or not self.is_attack_active or self.health <= 0
        
        obs = self._get_observation()
        obs.reward = float(max(0.01, min(0.99, reward)))
        obs.done = done
        obs.inspection_result = " | ".join(inspections) if inspections else None
        return obs

    @property
    def state(self) -> SecurityState:
        return SecurityState(
            episode_id="benchmark_run",
            step_count=self.current_step,
            is_under_attack=self.is_attack_active,
            attacker_ips=self.attackers,
            infrastructure_health=max(0.0, self.health),
            threat_level=self.mitre_map.get(self.task_id, "Unknown")
        )

    def _get_observation(self) -> SecurityObservation:
        new_logs = []
        for _ in range(25):
            rand = random.random()
            if rand < 0.15 and self.is_attack_active:
                source_ip = random.choice([a for a in self.attackers if a not in self.blocked_ips] or self.attackers)
                message = f"Alert: Potential {self.mitre_map[self.task_id]} behavior."
            else:
                source_ip = f"10.0.5.{random.randint(1, 255)}"
                message = "Heartbeat: Node operational."

            new_logs.append(LogEntry(timestamp=str(time.time()), source_ip=source_ip, destination_ip="10.0.0.1", port=80, protocol="TCP", message=message))
        return SecurityObservation(new_logs=new_logs, blocked_ips=list(self.blocked_ips), system_load=1.0-max(0.0, self.health), metrics={"health": float(self.health), "dwell_time": float(self.dwell_time)}, reward=0.01, done=False)

    def _calculate_reward(self, action: SecurityAction, targets: List[str]) -> float:
        # COST: Every inspection costs -0.02
        if action.action_type == ActionType.INSPECT_IP:
            return 0.18 # (+0.2 base - 0.02 cost)
            
        for t in targets:
            if action.action_type == ActionType.BLOCK_IP and t.startswith("10.0.") and t not in self.attackers:
                return 0.01 # Penalty for FP
                
        hit_count = len([t for t in targets if t in self.attackers])
        if action.action_type == ActionType.BLOCK_IP and hit_count > 0:
            # DWELL BONUS: High reward for catching them fast
            dwell_multiplier = max(0.5, 1.0 - (self.dwell_time * 0.05))
            return 0.99 * (hit_count / len(self.attackers)) * dwell_multiplier
            
        return 0.01

    def grade(self) -> float:
        # Grade = Health adjusted by efficiency (dwell and inspection cost)
        efficiency = max(0.5, 1.0 - (self.dwell_time * 0.02) - (self.investigation_count * 0.01))
        final_grade = self.health * efficiency
        return float(max(0.01, min(0.99, final_grade)))
