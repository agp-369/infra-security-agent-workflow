# 🛡️ Infra Security Agent Workflow (Finalist Submission)

## 🏆 Project Vision
A high-fidelity Reinforcement Learning (RL) environment for **Automated Incident Response**. Developed using the official Meta OpenEnv standard.

---

## 📐 Environment Specification
| Attribute | Specification |
| :--- | :--- |
| **Observation Space** | `Dict` (Logs, Metrics, Firewall State) |
| **Action Space** | `Discrete` / `Dict` (Investigate, Block, Allow, Quarantine) |
| **Grading** | Programmatic Deterministic Grader (0.01 - 0.99) |
| **Framework** | `openenv-core` v1.0.0 |

---

## 🔍 Task Library & Metadata
This environment implements 5 specialized security analyst workflows:
1.  **`workflow_brute_force`**: Detect high-frequency SSH attacks.
2.  **`workflow_sql_injection`**: Identify malicious payload signatures.
3.  **`workflow_credential_stuffing`**: Multi-IP adversarial defense.
4.  **`workflow_apt_mitigation`**: Temporal stealth and lateral movement.
5.  **`workflow_insider_threat`**: Contextual behavior analysis.

---

## 🧠 Reward & Grader Design
This environment uses **Dense Reward Shaping** to guide agent learning:
- **Investigation Reward ($R_{inv}$)**: +0.2
- **Mitigation Reward ($R_{mit}$)**: +1.0
- **Penalty ($P_{fp}$)**: -0.2 per False Positive.
- **Grader Formula**: $Grade = (0.6 \times Protection) + (0.4 \times Health) - False\_Positives$.

---

## 💻 Usage
1.  **Install**: `pip install .`
2.  **Run Inference**: `python inference.py`
3.  **Deployment**: HF Docker Space (Port 7860).
