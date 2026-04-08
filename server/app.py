import sys
import os
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Ensure the root directory is in the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from env.security_env import SecurityLogEnv
from env.models import SecurityAction, SecurityObservation, SecurityState

app = FastAPI(title="Infra Security Agent")

# Global environment instance
env = SecurityLogEnv()

class ActionRequest(BaseModel):
    action: SecurityAction

@app.get("/")
def read_root():
    return {"status": "healthy", "message": "SecurityLogEnv is live."}

@app.post("/reset", response_model=SecurityObservation)
def reset(task_id: str = "workflow_brute_force"):
    try:
        env.task_id = task_id
        obs = env.reset()
        return obs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/step", response_model=SecurityObservation)
def step(request: ActionRequest):
    try:
        obs = env.step(request.action)
        return obs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/state", response_model=SecurityState)
def get_state():
    return env.state

@app.get("/grade")
def get_grade():
    return {"grade": env.grade()}

def main():
    """CLI Entry point required by openenv validate."""
    uvicorn.run(app, host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()
