import sys
import os
import uvicorn
from fastapi import FastAPI, Body
from pydantic import BaseModel

# Ensure the 'src' directory is in the path for internal imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from infra_security_agent.server.environment import SecurityLogEnv
from infra_security_agent.models import SecurityAction, SecurityObservation, SecurityState
from openenv.core.env_server.types import ResetResponse, StepResponse, ResetRequest

app = FastAPI(title="Infra Security Agent")
env = SecurityLogEnv()

class ActionRequest(BaseModel):
    action: SecurityAction

@app.get("/")
def read_root():
    return {"status": "healthy"}

@app.post("/reset", response_model=ResetResponse)
def reset(request: ResetRequest = Body(default_factory=ResetRequest)):
    obs = env.reset()
    return ResetResponse(observation=obs.model_dump(), reward=obs.reward, done=obs.done)

@app.post("/step", response_model=StepResponse)
def step(request: ActionRequest):
    obs = env.step(request.action)
    return StepResponse(observation=obs.model_dump(), reward=obs.reward, done=obs.done)

@app.get("/state", response_model=SecurityState)
def get_state():
    return env.state

def main():
    uvicorn.run(app, host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()
