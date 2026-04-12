import sys
import os
import uvicorn
from fastapi import FastAPI, Body, HTTPException
from pydantic import BaseModel

# --- DOCKER COMPATIBILITY ---
# Ensure the project root is in the path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.append(root_dir)

# Absolute imports match the package structure
from env.security_env import SecurityLogEnv
from env.models import SecurityAction, SecurityObservation, SecurityState
from openenv.core.env_server.types import ResetResponse, StepResponse, ResetRequest

app = FastAPI(title="Infra Security Agent")
env = SecurityLogEnv()

class ActionRequest(BaseModel):
    action: SecurityAction

@app.get("/")
def read_root():
    return {"status": "healthy", "service": "InfraSecurityAgent"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/reset", response_model=ResetResponse)
def reset(request: ResetRequest = Body(default_factory=ResetRequest)):
    try:
        # Task ID extraction
        if hasattr(request, "task_id") and request.task_id: 
            env.task_id = request.task_id
        obs = env.reset()
        return ResetResponse(observation=obs.model_dump(), reward=obs.reward, done=obs.done)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/step", response_model=StepResponse)
def step(request: ActionRequest):
    try:
        obs = env.step(request.action)
        return StepResponse(observation=obs.model_dump(), reward=obs.reward, done=obs.done)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/state", response_model=SecurityState)
def get_state():
    return env.state

def main():
    # MANDATORY PORT 7860 for Hugging Face
    uvicorn.run(app, host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()
