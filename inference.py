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

# --- CONFIGURATION (Meta Hackathon Mandatory) ---
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.groq.com/openai/v1") 
MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.1-8b-instant") 

# Benchmark Settings
BENCHMARK = "infra-security-agent"
SUCCESS_THRESHOLD = 0.5

# --- LOGGING UTILS ---
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
        elif "query" in val: data["action_type"] = "query_logs"
        elif "noop" in val: data["action_type"] = "noop"
        return data
    except:
        return {"action_type": "noop"}

def run_task(client, task_id):
    env = SecurityLogEnv(task_id=task_id)
    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)
    
    obs = env.reset()
    done = False
    rewards: List[float] = [0.0100]
    steps = 0
    history_text: List[str] = []

    # THE EXPERT REASONING PROMPT
    SYSTEM_PROMPT = textwrap.dedent(
        """
        You are a SOC Analyst. MISSION: Mitigate threats while protecting health.
        
        PROTOCOL:
        1. Alerts are ambiguous. You MUST call 'query_logs' to reveal attacker IPs.
        2. Once IPs are revealed, use 'block_ip' on the malicious IP.
        3. Avoid blocking internal assets (10.0.1.5).
        4. Reply with exactly one JSON object: {"action_type": "...", "target": "...", "reason": "..."}
        """
    ).strip()

    try:
        for step in range(1, 15):
            if done: break
            steps = step
            
            user_prompt = textwrap.dedent(
                f"""
                ### STEP {step}/20
                ALERT: {obs.alert_text}
                FEEDBACK: {obs.error_context or 'None'}
                REVEALED LOGS: {obs.queried_logs if obs.queried_logs else 'None'}
                
                Execute your next security action.
                """
            ).strip()

            if API_KEY and "mock" not in str(API_KEY):
                completion = client.chat.completions.create(
                    model=MODEL_NAME, 
                    messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt}],
                    temperature=0.1 
                )
                action_data = repair_json(completion.choices[0].message.content)
            else:
                # Mock Logic for Baseline
                if not obs.queried_logs:
                    action_data = {"action_type": "query_logs", "target": "all"}
                else:
                    action_data = {"action_type": "block_ip", "target": obs.queried_logs[0].source_ip}

            action = SecurityAction(**action_data)
            obs = env.step(action)
            
            rewards.append(float(obs.reward))
            done = obs.done
            log_step(step=step, action=action.action_type, reward=obs.reward, done=done, error=obs.error_context if "ERROR" in str(obs.error_context) else None)

        score = env.grade()
        log_end(success=(score >= SUCCESS_THRESHOLD), steps=steps, score=score, rewards=rewards)
    except Exception as e:
        log_end(success=False, steps=steps, score=0.01, rewards=[0.01])

def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "mock_key")
    # Demonstrate on the hardest task
    run_task(client, "workflow_insider_threat")

if __name__ == "__main__":
    main()
