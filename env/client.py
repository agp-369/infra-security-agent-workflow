from typing import Optional, Any, Dict
from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from .models import SecurityAction, SecurityObservation, SecurityState

class SecurityEnvClient(EnvClient[SecurityAction, SecurityObservation, SecurityState]):
    """
    Kaggle-to-Space Bridge for GRPO Training.
    Wraps the OpenEnv Client to provide the interface TRL expects.
    """
    
    def __init__(self, base_url: str = "https://agp9-infra-security-agent.hf.space", **kwargs):
        # EnvClient init handles URL conversion
        super().__init__(base_url=base_url)
        self.last_result: Optional[StepResult[SecurityObservation]] = None

    def _step_payload(self, action: SecurityAction) -> Dict[str, Any]:
        """Convert action model to dictionary payload."""
        return action.model_dump()

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[SecurityObservation]:
        """Parse server response into a typed StepResult."""
        obs_data = payload.get("observation", {})
        observation = SecurityObservation(**obs_data)
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> SecurityState:
        """Parse state response into a typed SecurityState."""
        return SecurityState(**payload)

    def reset(self, **kwargs) -> StepResult[SecurityObservation]:
        """Reset the remote environment and store result."""
        self.last_result = super().reset(**kwargs)
        return self.last_result

    def step(self, action: SecurityAction, **kwargs) -> StepResult[SecurityObservation]:
        """Step the remote environment and store result."""
        self.last_result = super().step(action, **kwargs)
        return self.last_result

    @property
    def reward(self) -> float:
        """Helper for TRL reward functions to pull the most recent reward."""
        if self.last_result and self.last_result.reward is not None:
            return float(self.last_result.reward)
        return 0.01
