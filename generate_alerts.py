#!/usr/bin/env python3
"""Generate the alert dataset as a static JSON file for the web UI."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeder"))
from seed import build_dataset, NOW

data = {
    "generated_at": NOW.isoformat(),
    "alerts": build_dataset(),
}

out = sys.argv[1] if len(sys.argv) > 1 else "/dev/stdout"
with open(out, "w") as f:
    json.dump(data, f, separators=(",", ":"))
print(f"Generated {len(data['alerts'])} alerts", file=sys.stderr)
