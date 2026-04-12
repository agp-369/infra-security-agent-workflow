import os
# --- UNSLOTH FIX: DISABLE TELEMETRY TO PREVENT KAGGLE TIMEOUT ---
os.environ["UNSLOTH_DISABLE_TELEMETRY"] = "1"

import torch
from unsloth import FastLanguageModel
from datasets import Dataset

# --- ROBUST TRL IMPORTS ---
try:
    from trl.trainer.grpo_trainer import GRPOTrainer, GRPOConfig
except ImportError:
    from trl import GRPOTrainer, GRPOConfig

# --- 1. ENVIRONMENT CONFIGURATION ---
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

# --- 3. REINFORCEMENT LEARNING FROM VERIFIABLE REWARDS (RLVR) ---
def security_reward_func(prompts, completions, **kwargs):
    rewards = []
    for completion in completions:
        if "query_logs" in completion.lower() and "block_ip" not in completion.lower():
            rewards.append(0.3)
        elif "block_ip" in completion.lower() and "success" in completion.lower():
            rewards.append(0.99)
        elif "protocol violation" in completion.lower():
            rewards.append(0.01)
        elif "10.0.1.5" in completion:
            rewards.append(0.01)
        else:
            rewards.append(0.05)
    return rewards

# --- 4. DATASET PREPARATION ---
dataset = Dataset.from_dict({
    "prompt": [
        "Alert: SIEM flagged anomalous activity in segment-01. Protocol violation TA0001.",
        "Security Note: Potential lateral movement observed in internal development subnet.",
        "Anomaly detected: SIEM flagged mass data download originating from payroll subnet."
    ]
})

# --- 5. GRPO TRAINING CONFIGURATION ---
training_args = GRPOConfig(
    output_dir = "infra_security_agent_grpo",
    learning_rate = 5e-6,
    per_device_train_batch_size = 1,
    gradient_accumulation_steps = 4,
    num_generations = 8, 
    max_steps = 50,
    logging_steps = 1,
    bf16 = torch.cuda.is_bf16_supported(),
)

trainer = GRPOTrainer(
    model = model,
    reward_funcs = [security_reward_func],
    args = training_args,
    train_dataset = dataset,
)

if __name__ == "__main__":
    print("--- STARTING GRPO RL LOOP (Telemetry Disabled) ---")
    trainer.train()
    print("\nTraining Complete.")
    model.save_pretrained_merged("final_agent_model", tokenizer, save_method = "lora")
