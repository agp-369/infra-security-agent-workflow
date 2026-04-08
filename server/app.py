import sys
import os
import uvicorn
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

# Ensure the root directory is in the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from env.security_env import SecurityLogEnv
from env.models import SecurityAction, SecurityObservation, SecurityState
from openenv.core.env_server.types import ResetResponse, StepResponse, ResetRequest

app = FastAPI(title="Infra Security Agent")

# Global environment instance
env = SecurityLogEnv()

class ActionRequest(BaseModel):
    action: SecurityAction

@app.get("/")
def read_root():
    return {"status": "healthy", "message": "SecurityLogEnv is live."}

@app.post("/reset", response_model=ResetResponse)
def reset(request: ResetRequest = Body(default_factory=ResetRequest)):
    try:
        # Support task_id if passed in request or params
        if hasattr(request, "task_id"):
            env.task_id = request.task_id
        
        observation = env.reset()
        
        # Wrap in official ResetResponse
        return ResetResponse(
            observation=observation.model_dump(),
            reward=float(observation.reward) if observation.reward is not None else 0.01,
            done=observation.done
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/step", response_model=StepResponse)
def step(request: ActionRequest):
    try:
        observation = env.step(request.action)
        
        # Wrap in official StepResponse
        return StepResponse(
            observation=observation.model_dump(),
            reward=float(observation.reward) if observation.reward is not None else 0.01,
            done=observation.done
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/state", response_model=SecurityState)
def get_state():
    return env.state

@app.get("/grade")
def get_grade():
    return {"grade": env.grade()}

def main():
    uvicorn.run(app, host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()
