# Pipeline Policies

IAM policies and trust policies for the CI/CD pipeline execution role.

| File | Description |
|------|-------------|
| `role-assume-policy.json` | IAM policy allowing the pipeline role to assume deployment roles in target accounts |
| `role-trust-policy.json` | Trust policy for the pipeline role (supports CodePipeline, ECS, or external pipeline types) |
