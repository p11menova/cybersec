"""Summarize real scanner output for GitHub Actions screenshots."""

import json
import sys
from pathlib import Path

kind, filename = sys.argv[1:]
print(f"## {kind} security report\n")
path = Path(filename)
if not path.exists():
    print("Report unavailable: the scanner did not complete. See the failed step's log.")
    sys.exit(0)
data = json.loads(path.read_text())
if kind == "bandit":
    print(f"Findings: **{len(data['results'])}**. Scanner errors: **{len(data['errors'])}**.")
    print(f"\nLines scanned: {data['metrics']['_totals']['loc']}.")
elif kind == "snyk":
    if "error" in data:
        print("Scan error; see the Snyk step log. No successful result is available.")
    else:
        count = len(data.get("vulnerabilities", []))
        print(f"Reported vulnerabilities at High/Critical threshold: **{count}**.")
        print(f"\nSnyk ok: **{data.get('ok', 'unavailable')}**.")
print("\nFull JSON report is in this run's Artifacts. The step exit status determines success.")
