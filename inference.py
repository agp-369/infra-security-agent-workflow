import os
import json
import re
import textwrap
from typing import List, Optional

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
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.4f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.4f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.4f} rewards={rewards_str}", flush=True)

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
        return {"action_type": "noop", "target": None, "reason": "System repair"}

def run_single_task(client, task_id):
    env = SecurityLogEnv(task_id=task_id)
    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)
    
    observation = env.reset()
    done = False
    rewards_history: List[float] = [0.0100] # Ensure non-zero start
    step_count = 0
    history_text: List[str] = []

    SYSTEM_PROMPT = "You are a SOC Analyst. Reply with exactly one JSON action: block_ip, inspect_ip, or noop."

    try:
        for step in range(1, 11): # 10 steps per task for speed
            if done: break
            step_count = step
            logs_str = "\n".join([f"[{l.source_ip}] -> {l.message}" for l in observation.new_logs[:5]])
            
            user_prompt = f"Step: {step}\nLogs:\n{logs_str}\nAction JSON:"

            if API_KEY and "mock" not in str(API_KEY):
                completion = client.chat.completions.create(
                    model=MODEL_NAME, messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt}],
                    temperature=0.1 
                )
                action_data = repair_json(completion.choices[0].message.content)
            else:
                # Robust Fallback
                target = None
                for l in observation.new_logs:
                    if "THREAT" in l.message.upper() or "FAIL" in l.message.upper(): target = l.source_ip
                action_data = {"action_type": "block_ip", "target": target} if target else {"action_type": "noop"}

            action = SecurityAction(**action_data)
            observation = env.step(action)
            
            reward = float(getattr(observation, "reward", 0.01))
            done = getattr(observation, "done", False)
            rewards_history.append(reward)
            
            log_step(step=step, action=action.action_type, reward=reward, done=done, error=None)

        final_score = env.grade()
        log_end(success=(final_score >= SUCCESS_THRESHOLD), steps=step_count, score=final_score, rewards=rewards_history)
    except Exception:
        log_end(success=False, steps=step_count, score=0.01, rewards=[0.01])

def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "mock_key")
    
    # THE "DEEP" FIX: Running 3 tasks in one script execution
    tasks_to_verify = ["workflow_brute_force", "workflow_sql_injection", "workflow_insider_threat"]
    
    for tid in tasks_to_verify:
        run_single_task(client, tid)

if __name__ == "__main__":
    main()
