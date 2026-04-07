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

# Configuration (Strict Checklist Compliance)
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.groq.com/openai/v1") 
MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.1-8b-instant") 
HF_TOKEN = os.getenv("HF_TOKEN") # No default as per checklist

# Meta Logging Functions (Strict key=value format)
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

def repair_json(text: str) -> dict:
    """Extracts and repairs JSON from LLM response."""
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

def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN or "mock_key")
    env = SecurityLogEnv(task_id="workflow_credential_stuffing")
    
    benchmark_name = "infra-security-agent"
    log_start(task=env.task_id, env=benchmark_name, model=MODEL_NAME)
    
    observation = env.reset()
    done = False
    rewards_history: List[float] = []
    step_count = 0
    history_text: List[str] = []

    try:
        while not done and step_count < 20:
            step_count += 1
            logs_str = "\n".join([f"[{l.source_ip}] -> {l.message}" for l in observation.new_logs])
            
            system_prompt = (
                "You are a Senior Security Analyst. MISSION: Protect Infrastructure Health.\n"
                "Use 'inspect_ip' or 'block_ip'. Return valid JSON.\n"
                "JSON: {\"action_type\": \"...\", \"target\": \"...\", \"reason\": \"...\"}"
            )
            
            user_prompt = (
                f"### CONTEXT: STEP {step_count}/20\n"
                f"### INVESTIGATION: {observation.inspection_result}\n"
                f"### HISTORY:\n{chr(10).join(history_text[-3:])}\n\n"
                f"### LIVE LOGS:\n{logs_str}\n"
            )

            if HF_TOKEN:
                completion = client.chat.completions.create(
                    model=MODEL_NAME, 
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                    temperature=0.1 
                )
                action_data = repair_json(completion.choices[0].message.content)
            else:
                # Mock logic for local testing
                target = None
                for l in observation.new_logs:
                    if "STUFFING" in l.message: target = l.source_ip
                action_data = {"action_type": "block_ip", "target": target, "reason": "Mock"} if target else {"action_type": "noop", "target": None, "reason": "Mock"}

            action = SecurityAction(**action_data)
            observation = env.step(action)
            
            reward = float(getattr(observation, "reward", 0.0) or 0.0)
            done = getattr(observation, "done", False)
            rewards_history.append(reward)
            
            # [STEP] Mandatory Log
            log_step(step=step_count, action=action.action_type, reward=reward, done=done, error=None)
            
            history_text.append(f"Step {step_count}: {action.action_type} on {action.target}. Reward: {reward}")

            if done: break

        # Final Grade and Success
        final_grade = env.grade()
        log_end(success=(final_grade > 0.5), steps=step_count, score=final_grade, rewards=rewards_history)

    except Exception as e:
        log_end(success=False, steps=step_count, score=0.0, rewards=rewards_history)

if __name__ == "__main__":
    main()
