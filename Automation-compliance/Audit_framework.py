# minimal_audit.py - Start with this!
import os
import json
from datetime import datetime

findings = []

# Test 1: Check if we can write files
try:
    os.makedirs("audit_output", exist_ok=True)
    findings.append({"check": "File Write", "status": "PASS"})
except:
    findings.append({"check": "File Write", "status": "FAIL"})

# Test 2: Check a file that always exists
if os.path.exists("/etc/passwd"):  # Linux
    findings.append({"check": "File Read", "status": "PASS"})

# Export
with open("audit_output/test.json", "w") as f:
    json.dump(findings, f, indent=2)

print("Minimal audit complete - check audit_output/test.json")