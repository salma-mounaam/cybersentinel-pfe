import json
import time

alerts = [
    {"severity": 1, "signature": "ET EXPLOIT SQL Injection Attempt", "src_ip": "10.0.0.100", "dest_ip": "192.168.1.10", "mitre": "T1190"},
    {"severity": 2, "signature": "ET SCAN Port Scan Detected", "src_ip": "10.0.0.200", "dest_ip": "192.168.1.10", "mitre": "T1046"},
    {"severity": 3, "signature": "ET MALWARE CnC Beacon", "src_ip": "10.0.0.150", "dest_ip": "8.8.8.8", "mitre": "T1071"},
]

with open("/var/log/suricata/eve.json", "a") as f:
    for a in alerts:
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000"),
            "event_type": "alert",
            "src_ip": a["src_ip"],
            "src_port": 4444,
            "dest_ip": a["dest_ip"],
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2100000,
                "rev": 1,
                "signature": a["signature"],
                "category": "Attack",
                "severity": a["severity"],
                "metadata": {"mitre_technique": a["mitre"]},
            },
        }
        f.write(json.dumps(event) + "\n")
        f.flush()
        time.sleep(0.5)
        print("Alerte injectée :", a["signature"])
