import sys
import os

# Ensure the root directory is in the path so imports from 'env' work
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openenv.core.env_server.http_server import create_app
from env.security_env import SecurityLogEnv
from env.models import SecurityAction, SecurityObservation

# 🛠️ The official OpenEnv way to create the application
app = create_app(
    SecurityLogEnv,
    SecurityAction,
    SecurityObservation,
    env_name="infra-security-agent",
    max_concurrent_envs=1
)

# 🚀 Mandatory Root Endpoint for 200 OK Ping
@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "env": "infra-security-agent",
        "message": "SecurityLogEnv is running on port 7860."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
