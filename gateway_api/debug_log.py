import json
from datetime import datetime

def log_request(stage, data):
    with open('/tmp/gateway_debug.log', 'a') as f:
        f.write(f"\n=== {datetime.now().isoformat()} - {stage} ===\n")
        f.write(json.dumps(data, indent=2, default=str))
        f.write("\n")
