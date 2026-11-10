#!/usr/bin/env python3
"""Test if base.tfvars can be parsed by checking for HCL syntax issues."""
# bandit B404: a developer script; its one call below is a fixed argv
import subprocess, json  # nosec B404

# Try to parse base.tfvars with terraform
# bandit B603/B607: fixed argv and fixed stdin, no shell, no outside input; terraform from PATH as the Makefile calls it
result = subprocess.run(  # nosec B603 B607
    ["terraform", "console"],
    input='var.security_hub_standards',
    capture_output=True, text=True,
    cwd="modules/security"
)
print("stdout:", result.stdout.strip())
print("stderr:", result.stderr.strip()[:500] if result.stderr else "")
