from typing import Optional, Any, Dict
from openenv.core import EnvClient
from .models import SecurityAction, SecurityObservation, SecurityState

class SecurityEnvClient(EnvClient[SecurityAction, SecurityObservation, SecurityState]):
    """
    Kaggle-to-Space Bridge for GRPO Training.
    Wraps the OpenEnv Client to provide the interface TRL expects.
    """
    
    def __init__(self, base_url: str = "https://agp9-infra-security-agent.hf.space", **kwargs):
        # Allow passing the task_id via kwargs if TRL needs it
        task_id = kwargs.get("task_id", "workflow_apt_mitigation")
        super().__init__(base_url=base_url, task_id=task_id)
        self.last_obs: Optional[SecurityObservation] = None

    def reset(self, **kwargs) -> SecurityObservation:
        """Reset the remote environment and store observation."""
        self.last_obs = super().reset(**kwargs)
        return self.last_obs

    def step(self, action: SecurityAction) -> SecurityObservation:
        """Step the remote environment and store reward."""
        self.last_obs = super().step(action)
        return self.last_obs

    @property
    def reward(self) -> float:
        """Helper for TRL reward functions."""
        return float(self.last_obs.reward) if self.last_obs else 0.01
