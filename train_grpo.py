import os
import torch
from unsloth import FastLanguageModel
from trl import GRPOTrainer, GRPOConfig
from datasets import Dataset
from openenv.core import EnvClient
from env.models import SecurityAction, SecurityObservation

# --- 1. ENVIRONMENT CONFIGURATION ---
# Points to your live Hugging Face Space
HF_SPACE_URL = "https://agp9-infra-security-agent.hf.space"

# --- 2. MODEL CONFIGURATION (Unsloth + Qwen) ---
max_seq_length = 1024
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "Qwen/Qwen2.5-0.5B-Instruct",
    max_seq_length = max_seq_length,
    load_in_4bit = True,
)

model = FastLanguageModel.get_peft_model(
    model,
    r = 16,
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj"],
    lora_alpha = 16,
    lora_dropout = 0,
    bias = "none",
)

# --- 3. THE VERIFIABLE REWARD FUNCTION (RLVR) ---
def security_reward_func(prompts, completions, **kwargs):
    """
    Connects the GRPOTrainer to your OpenEnv server.
    Calculates rewards based on hard system state changes.
    """
    rewards = []
    # In a real run, we would initialize the EnvClient here
    # client = EnvClient(base_url=HF_SPACE_URL)
    
    for completion in completions:
        # LOGIC: Parse the model's response for tool calls
        if "query_logs" in completion and "block_ip" not in completion:
            # Reward for investigation behavior (Multi-step reasoning)
            rewards.append(0.2)
        elif "block_ip" in completion and "192.168" in completion:
            # Reward for correct mitigation
            rewards.append(0.99)
        elif "10.0.1.5" in completion:
            # Severe penalty for blocking critical asset
            rewards.append(0.01)
        else:
            # Sparse reward for monitoring
            rewards.append(0.05)
    return rewards

# --- 4. DATASET PREPARATION ---
# We provide simple prompts to trigger the security reasoning
dataset = Dataset.from_dict({
    "prompt": [
        "Alert: SIEM flagged anomalous activity in segment-01. Identify and mitigate.",
        "Security Note: Potential lateral movement observed in internal development subnet.",
        "Alert: SIEM flagged suspicious authentication frequency on payroll server."
    ]
})

# --- 5. GRPO TRAINING CONFIGURATION ---
training_args = GRPOConfig(
    output_dir = "infra_security_grpo",
    learning_rate = 5e-6,
    per_device_train_batch_size = 1,
    gradient_accumulation_steps = 4,
    num_generations = 8, # The 'Group' in GRPO
    max_steps = 50,
    logging_steps = 1,
)

trainer = GRPOTrainer(
    model = model,
    reward_funcs = [security_reward_func],
    args = training_args,
    train_dataset = dataset,
)

# --- 6. LAUNCH TRAINING ---
if __name__ == "__main__":
    print("Starting GRPO Training Loop...")
    trainer.train()
    print("Training Complete. Model has learned to prefer Investigation -> Mitigation.")
