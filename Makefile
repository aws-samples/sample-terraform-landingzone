# Makefile for Terraform Landing Zone
#
# Required tools:
#   terraform  >= 1.14
#   terragrunt >= 1.0    (HCL format check)
#   tflint     >= 0.50   (configured by .tflint.hcl)
#   checkov    >= 3.0    (configured by .checkov.yaml)
#   python3    >= 3.11   with pytest and hypothesis
#
# Usage:
#   make init      - Initialize every module (no backend)
#   make fmt       - Check formatting (Terraform and HCL)
#   make validate  - Terraform validation of every module and customization
#   make lint      - Run TFLint
#   make scan      - Forbidden execution pattern check + Checkov scan
#   make test      - Run Terraform tests + Python tests

.PHONY: init fmt validate lint scan test

# Directories holding Terragrunt/HCL configuration (checked by `fmt`)
HCL_DIRS := stacks configurations env

# Code areas searched by the pattern checks of `scan`
CODE_AREAS := modules stacks configurations customizations env

# Override to select another interpreter: `make test PYTEST="python3.12 -m pytest"`.
PYTEST ?= python3 -m pytest

# Initialize Terraform (all modules)
init:
	@for dir in modules/*/; do \
		echo "=== Init: $$dir ==="; \
		terraform -chdir=$$dir init -backend=false || exit 1; \
	done

# Check formatting (non-destructive). terraform fmt handles .tf and .tfvars only;
# terragrunt checks the HCL of the stacks, configurations and env examples.
fmt:
	@echo "=== Terraform Format ==="
	terraform fmt -check -recursive -diff
	@for dir in $(HCL_DIRS); do \
		echo "=== HCL Format: $$dir ==="; \
		terragrunt hcl format --check --diff --working-dir $$dir || exit 1; \
	done

# Terraform validation (all modules and all customization modules)
validate: init
	@for dir in modules/*/; do \
		echo "=== Validate: $$dir ==="; \
		terraform -chdir=$$dir validate || exit 1; \
	done
	@for dir in customizations/*/; do \
		echo "=== Validate: $$dir ==="; \
		terraform -chdir=$$dir init -backend=false || exit 1; \
		terraform -chdir=$$dir validate || exit 1; \
	done

# TFLint with the AWS ruleset in every module and customization directory that holds
# a .tf file. Errors fail the target; warnings are printed.
lint:
	tflint --init --config "$(CURDIR)/.tflint.hcl"
	@n=0; for dir in modules/*/ customizations/*/; do \
		ls "$$dir"*.tf > /dev/null 2>&1 || continue; \
		echo "=== TFLint: $$dir ==="; \
		tflint --chdir="$$dir" --config "$(CURDIR)/.tflint.hcl" --minimum-failure-severity=error || exit 1; \
		n=$$((n + 1)); \
	done; \
	if [ "$$n" -eq 0 ]; then echo "lint: no directory with a .tf file found - nothing was inspected" >&2; exit 1; fi; \
	echo "lint: $$n directories inspected"

# Forbidden execution patterns (local-exec/remote-exec provisioners, external data
# sources), then the Checkov security scan
scan:
	@echo "=== Forbidden Execution Patterns ==="
	@if grep -rn 'provisioner "local-exec"' --include='*.tf' $(CODE_AREAS) 2>/dev/null; then \
		echo "ERROR: local-exec provisioner found!"; exit 1; \
	fi
	@if grep -rn 'provisioner "remote-exec"' --include='*.tf' $(CODE_AREAS) 2>/dev/null; then \
		echo "ERROR: remote-exec provisioner found!"; exit 1; \
	fi
	@if grep -rn 'data "external"' --include='*.tf' $(CODE_AREAS) 2>/dev/null; then \
		echo "ERROR: external data source found!"; exit 1; \
	fi
	@echo "No forbidden execution patterns found."
	@echo "=== Checkov Security Scan ==="
	env -u PYTHONPATH -u PYTHONHOME checkov -d . --config-file .checkov.yaml

# Terraform tests (all modules, and every customization module with a tests/ directory)
# and the Python tests
test: init
	@for dir in modules/*/; do \
		echo "=== Test: $$dir ==="; \
		terraform -chdir=$$dir test || exit 1; \
	done
	@for dir in customizations/*/; do \
		if [ -d "$$dir/tests" ]; then \
			echo "=== Test: $$dir ==="; \
			terraform -chdir=$$dir init -backend=false || exit 1; \
			terraform -chdir=$$dir test || exit 1; \
		else \
			echo "=== Skip (no tests/): $$dir ==="; \
		fi; \
	done
	@echo "=== Python Tests ==="
	$(PYTEST) tests/ -q
