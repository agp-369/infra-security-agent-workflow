# 🛡️ Infra Security Agent Workflow (Benchmark Edition)

## 🏆 Project Overview
The **Infra Security Agent Workflow** is a high-fidelity Reinforcement Learning (RL) environment designed to train and benchmark AI agents for **Automated Incident Response**. Developed for the **Meta PyTorch Hackathon Round 1 (OpenEnv)**.

---

## 🏗️ The 3 Pillars of Excellence (Scientific Design)
This environment is built to address the unique challenges of RL in cybersecurity:

1.  **MITRE ATT&CK Alignment**: Every adversarial task is mapped to real-world tactics (e.g., **TA0008: Lateral Movement**).
2.  **Dwell-Time Penalties**: The reward function is non-linear—agents are penalized for every turn a hacker remains active in the system.
3.  **Investigation Economics**: The `inspect_ip` tool provides vital intelligence but carries a **Resource Cost**, forcing agents to balance reasoning against data-gathering.

---

## 📐 Environment Specification
| Attribute | Specification |
| :--- | :--- |
| **Observation Space** | `Dict` (Logs, Metrics, Firewall State) |
| **Action Space** | `Discrete` / `Dict` (Investigate, Block, Allow, Quarantine) |
| **Grading** | Efficiency-Adjusted Health Score (0.01 - 0.99) |
| **Framework** | `openenv-core` v1.0.0 |

---

## 🔍 Task Library & MITRE Mapping
1.  **Credential Access (T1110)**: Detect high-frequency authentication failures.
2.  **Public Exploit (T1190)**: Identify malicious SQL payload signatures.
3.  **Credential Stuffing (T1110.004)**: Multi-IP distributed defense.
4.  **Lateral Movement (TA0008)**: Navigate silent phases and internal pivots.
5.  **Data Exfiltration (TA0010)**: Contextual awareness of unauthorized downloads.

---

## 🧠 Reward Shaping
$Score = Health \times (1.0 - Dwell\_Penalty - Cost\_Penalty)$
- **$R_{mit}$**: +0.99 (Success)
- **$R_{inv}$**: +0.18 (Intelligence Gathering with cost)
- **Penalty**: Direct degradation of health per turn per threat.

---

## 📊 Baseline Scores
Verified reproducible scores from `inference.py` (v5.0 Benchmark):
| Task ID | Level | Baseline Score |
| :--- | :--- | :--- |
| `workflow_brute_force` | Easy | 0.990 |
| `workflow_sql_injection` | Medium | 0.990 |
| `workflow_credential_stuffing` | Medium | 0.982 |
| `workflow_apt_mitigation` | Hard | 0.990 |
| `workflow_insider_threat` | Hard | 0.990 |

---

## 💻 Setup & Submission
1. **Local Test**: `python inference.py`
2. **Deploy**: HF Docker Space (Port 7860).
