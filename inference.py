import os
import json
import re
import textwrap
from typing import List, Optional

import sys
import os

# Ensure the 'src' directory is in the path for local testing
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from dotenv import load_dotenv
from openai import OpenAI
from env.security_env import SecurityLogEnv
from env.models import SecurityAction, ActionType

load_dotenv()

# --- CONFIGURATION ---
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.groq.com/openai/v1") 
MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.1-8b-instant") 
BENCHMARK = "infra-security-agent"
SUCCESS_THRESHOLD = 0.5

# --- LOGGING ---
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error if error else 'null'}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

def repair_json(text: str) -> dict:
    try:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        data = json.loads(match.group(0)) if match else json.loads(text)
        val = str(data.get("action_type", "")).lower()
        if "block" in val: data["action_type"] = "block_ip"
        elif "inspect" in val or "investigat" in val: data["action_type"] = "inspect_ip"
        elif "noop" in val or "none" in val: data["action_type"] = "noop"
        return data
    except Exception:
        return {"action_type": "noop"}

def run_task(client, task_id):
    env = SecurityLogEnv(task_id=task_id)
    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)
    
    obs = env.reset()
    done = False
    rewards: List[float] = [0.0100]
    steps = 0

    try:
        for step in range(1, 11):
            if done: break
            steps = step
            
            if API_KEY and "mock" not in str(API_KEY):
                user_prompt = f"Step: {step}\nLogs:\n{obs.new_logs[:5]}\nAction JSON:"
                completion = client.chat.completions.create(
                    model=MODEL_NAME, messages=[{"role": "user", "content": user_prompt}],
                    temperature=0.1 
                )
                action_data = repair_json(completion.choices[0].message.content)
            else:
                # UPDATED SIGNATURE MATCHER (Recognizes MITRE tags)
                target = None
                for l in obs.new_logs:
                    if "POTENTIAL" in l.message.upper() or "ALERT" in l.message.upper():
                        target = l.source_ip
                        break
                action_data = {"action_type": "block_ip", "target": target} if target else {"action_type": "noop"}

            action = SecurityAction(**action_data)
            obs = env.step(action)
            reward = float(obs.reward)
            done = obs.done
            rewards.append(reward)
            log_step(step=step, action=action.action_type, reward=reward, done=done, error=None)

        score = env.grade()
        log_end(success=(score >= SUCCESS_THRESHOLD), steps=steps, score=score, rewards=rewards)
    except Exception:
        log_end(success=False, steps=steps, score=0.01, rewards=[0.01])

def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "mock_key")
    tasks = ["workflow_brute_force", "workflow_sql_injection", "workflow_credential_stuffing", "workflow_apt_mitigation", "workflow_insider_threat"]
    for tid in tasks:
        run_task(client, tid)

if __name__ == "__main__":
    main()
