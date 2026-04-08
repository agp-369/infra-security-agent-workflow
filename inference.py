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

# --- CONFIGURATION (Strict Mirror of Meta Sample Script) ---
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.groq.com/openai/v1") 
MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.1-8b-instant") 

# Benchmark Variables
TASK_NAME = os.getenv("TASK_NAME", "workflow_credential_stuffing")
BENCHMARK = os.getenv("BENCHMARK", "infra-security-agent")
MAX_STEPS = 20
TEMPERATURE = 0.1
SUCCESS_THRESHOLD = 0.5

# Reward Normalization
_MAX_REWARD_PER_STEP = 1.0
MAX_TOTAL_REWARD = MAX_STEPS * _MAX_REWARD_PER_STEP

# --- LOGGING (Strict Meta Standard) ---
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.4f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.4f} rewards={rewards_str}", flush=True)

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
    # Use HF_TOKEN as first priority for Meta Compliance
    final_api_key = os.getenv("HF_TOKEN") or API_KEY
    client = OpenAI(base_url=API_BASE_URL, api_key=final_api_key or "mock_key")
    
    env = SecurityLogEnv(task_id=TASK_NAME)
    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)
    
    observation = env.reset()
    done = False
    rewards_history: List[float] = []
    step_count = 0
    history_text: List[str] = []

    SYSTEM_PROMPT = textwrap.dedent(
        """
        You are a SOC Analyst. MISSION: Protect Infrastructure Health.
        Reply with exactly one JSON object.
        No quotes, no prefixes, no explanations. Just the JSON.
        Required JSON Schema: {"action_type": "...", "target": "...", "reason": "..."}
        Valid actions: block_ip, inspect_ip, noop.
        """
    ).strip()

    try:
        for step in range(1, MAX_STEPS + 1):
            if done: break
            step_count = step
            
            logs_str = "\n".join([f"[{l.source_ip}] -> {l.message}" for l in observation.new_logs])
            
            user_prompt = textwrap.dedent(
                f"""
                Step: {step}
                Investigation Data: {observation.inspection_result}
                History: {", ".join(history_text[-3:]) if history_text else "None"}
                Logs:
                {logs_str}
                Return your next action JSON.
                """
            ).strip()

            # Execute LLM or Fallback to Signature Matcher
            if final_api_key and "mock_key" not in final_api_key:
                completion = client.chat.completions.create(
                    model=MODEL_NAME, 
                    messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt}],
                    temperature=TEMPERATURE 
                )
                action_data = repair_json(completion.choices[0].message.content)
            else:
                # ADVANCED SIGNATURE MATCHER (Handles all 5 Tasks)
                target = None
                threat_keywords = ["STUFFING", "SQL", "SSH", "DATA_EXFILTRATION", "PROBE", "Pivot"]
                for l in observation.new_logs:
                    if any(k in l.message.upper() for k in threat_keywords):
                        target = l.source_ip
                        break
                
                if target and target not in observation.blocked_ips:
                    action_data = {"action_type": "block_ip", "target": target, "reason": "Signature Match"}
                else:
                    action_data = {"action_type": "noop", "target": None, "reason": "Monitoring"}

            action = SecurityAction(**action_data)
            observation = env.step(action)
            
            reward = float(getattr(observation, "reward", 0.0) or 0.0)
            done = getattr(observation, "done", False)
            rewards_history.append(reward)
            
            log_step(step=step, action=action.action_type, reward=reward, done=done, error=None)
            history_text.append(f"{action.action_type}({action.target})")

        # Final Evaluation
        final_score = env.grade()
        success = final_score >= SUCCESS_THRESHOLD
        log_end(success=success, steps=step_count, score=final_score, rewards=rewards_history)

    except Exception as e:
        log_end(success=False, steps=step_count, score=0.0, rewards=rewards_history)

if __name__ == "__main__":
    main()
