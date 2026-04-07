import os
import json
import re
from typing import List, Optional

from dotenv import load_dotenv
from openai import OpenAI
from env.security_env import SecurityLogEnv
from env.models import SecurityAction, ActionType

load_dotenv()

# Configuration (Strictly following Meta Submission Checklist Syntax)
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.groq.com/openai/v1") 
MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.1-8b-instant") 
HF_TOKEN = os.getenv("HF_TOKEN") # No default here as per checklist

def repair_json(text: str) -> dict:
    """Extracts and repairs JSON from LLM response."""
    try:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        data = json.loads(match.group(0)) if match else json.loads(text)
        val = str(data.get("action_type", "")).lower()
        if "block" in val: data["action_type"] = "block_ip"
        elif "inspect" in val or "investigat" in val: data["action_type"] = "inspect_ip"
        elif "quarantine" in val: data["action_type"] = "quarantine_file"
        elif "noop" in val or "none" in val: data["action_type"] = "noop"
        return data
    except Exception:
        return {"action_type": "noop", "target": None, "reason": "System repair"}

def main():
    # Use OpenAI client as strictly required
    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN or "mock_key")
    
    # Starting with a standard benchmark task
    env = SecurityLogEnv(task_id="workflow_credential_stuffing")
    
    # [START] MANDATORY LOG FORMAT
    print(f'[START] {json.dumps({"task_id": env.task_id})}')
    
    observation = env.reset()
    done = False
    total_reward = 0.0
    step_count = 0
    history: List[str] = []

    while not done and step_count < 20:
        step_count += 1
        logs_str = "\n".join([f"[{l.source_ip}] -> {l.message}" for l in observation.new_logs])
        
        system_prompt = (
            "You are a Senior Security Analyst. Use 'inspect_ip' or 'block_ip'.\n"
            "Return valid JSON: {\"action_type\": \"...\", \"target\": \"...\", \"reason\": \"...\"}"
        )
        
        user_prompt = (
            f"### CONTEXT: STEP {step_count}/20\n"
            f"### INVESTIGATION: {observation.inspection_result}\n"
            f"### HISTORY:\n{chr(10).join(history[-3:])}\n\n"
            f"### LIVE LOGS:\n{logs_str}\n"
        )

        try:
            if HF_TOKEN:
                completion = client.chat.completions.create(
                    model=MODEL_NAME, 
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                    temperature=0.1 
                )
                action_data = repair_json(completion.choices[0].message.content)
            else:
                # Fallback for local testing without key
                target = None
                for l in observation.new_logs:
                    if "STUFFING" in l.message or "High freq" in l.message: target = l.source_ip
                action_data = {"action_type": "block_ip", "target": target, "reason": "Mock"} if target else {"action_type": "noop", "target": None, "reason": "Mock"}

            action = SecurityAction(**action_data)
            observation = env.step(action)
            
            reward = float(getattr(observation, "reward", 0.0) or 0.0)
            done = getattr(observation, "done", False)
            total_reward += reward
            
            # [STEP] MANDATORY LOG FORMAT
            step_log = {
                "step": step_count,
                "action": action.action_type,
                "target": action.target,
                "reward": reward,
                "done": done
            }
            print(f'[STEP] {json.dumps(step_log)}')
            
            history.append(f"Step {step_count}: {action.action_type} on {action.target}. Reward: {reward}")

            if done: break

        except Exception as e:
            # Prevent hard crash, emit end log with current progress
            break

    # [END] MANDATORY LOG FORMAT
    end_log = {
        "total_reward": total_reward,
        "grade": env.grade(),
        "status": "success" if env.grade() > 0.5 else "failed"
    }
    print(f'[END] {json.dumps(end_log)}')

if __name__ == "__main__":
    main()
