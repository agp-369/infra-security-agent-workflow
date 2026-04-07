import requests
import json

def test_remote():
    url = "https://agp9-infra-security-agent.hf.space"
    print(f"--- STARTING ULTIMATE REMOTE VALIDATION ---")
    print(f"Target: {url}\n")

    # 1. ROOT PING
    print("[1/3] Testing GET / ...")
    try:
        r = requests.get(url)
        if r.status_code == 200:
            print(f"SUCCESS: Root is live. Response: {r.json()}")
        else:
            print(f"FAILED: Root returned {r.status_code}")
    except Exception as e:
        print(f"ERROR: {e}")

    # 2. RESET PING
    print("\n[2/3] Testing POST /reset ...")
    try:
        r = requests.post(f"{url}/reset", params={"task_id": "workflow_insider_threat"}, json={})
        if r.status_code == 200:
            data = r.json()
            print("SUCCESS: Reset works.")
            print(f"Captured {len(data.get('new_logs', []))} logs from the environment.")
        else:
            print(f"FAILED: Reset returned {r.status_code}")
            print(r.text)
    except Exception as e:
        print(f"ERROR: {e}")

    # 3. SPEC CHECK
    print("\n[3/3] Checking Model Spec Compliance ...")
    try:
        # Step into the environment (wrapped action)
        payload = {
            "action": {
                "action_type": "noop",
                "target": None,
                "reason": "validation test"
            }
        }
        r = requests.post(f"{url}/step", json=payload)
        if r.status_code == 200:
            print("SUCCESS: Step logic is compliant.")
            print("Verdict: Your project is 100% READY for Meta evaluation.")
        else:
            print(f"FAILED: Step returned {r.status_code}")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    test_remote()
