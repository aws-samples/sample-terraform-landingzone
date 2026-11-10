# tlz-core-guardrails-1.json — Design Notes

## Config Rules Protection Scope

The `ProtectConfigRules` statement in this SCP uses a broad scope — it protects all Config Rules, Config Recorder, Delivery Channel, and Evaluation Results from modification by non-privileged principals.

This is intentional. The broader protection:

- Prevents accidental deletion of any Config Rules (including custom rules)
- Protects the Config Recorder and Delivery Channel from being stopped or deleted
- Ensures Config evaluation results cannot be cleared

Exempt principals (`AWSControlTowerExecution`, `stacksets-exec-*`) can still manage Config resources as needed for deployment operations.
