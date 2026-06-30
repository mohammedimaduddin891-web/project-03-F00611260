Project 3 — Catch the Impostor

Files in this repository:

catch.py
auth_events.csv
ground_truth.csv
impossible_travel.py
output/run_output.txt
REPORT.docx
README.txt

Command to copy the result of my last tuned run:
python3 catch.py auth_events.csv --truth ground_truth.csv --threshold-kmh 3000

What this pipeline identifies:

Travel distance in Haversine distance mode, impossible mode.
off-hours privileged access
brute-force login behavior
password-spray behavior
very simple privilege escalation using a new role that has never been encountered before.

Tuning note:
To minimize the benign false positives, I set a more stringent impossible-travel threshold for the final run, but still found the planted suspicious travel event.

