import urllib.request
import json
import time

def trigger_brute_force():
    print("Sending 5 FAILED_LOGIN events to trigger Brute Force detection...")
    for i in range(5):
        payload = json.dumps({"type": "FAILED_LOGIN", "source_ip": "10.0.0.99"}).encode()
        req = urllib.request.Request("http://localhost:9000/gateway", data=payload, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req)
        print(f"Sent attempt {i+1}...")
        time.sleep(0.1)

if __name__ == "__main__":
    try:
        trigger_brute_force()
        print("\nSuccess! Check your agent terminal for the BRUTE_FORCE_DETECTED alert (Visibility: Backend).")
    except Exception as e:
        print(f"Failed to connect to agent: {e}\nMake sure the agent is running on port 9000.")
