SHELL := /bin/bash
PY := python3
TF := terraform -chdir=infra

.PHONY: help install build test patterns lint fmt coverage validate deploy plan destroy attack timing evidence clean

help: ## show targets
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t -s $$'\t'

install: ## dev dependencies
	$(PY) -m pip install -r requirements-dev.txt

build: ## stage the Lambda deployment package into build/lambda
	./scripts/build-lambda.sh

test: ## unit tests — fixtures + moto, no AWS account needed
	pytest tests/ -v

patterns: ## B2 gate — replay every fixture through EventBridge itself; needs credentials, not a deployed stack
	./scripts/verify-patterns.sh

lint: ## ruff + mypy + terraform static analysis
	ruff check .
	ruff format --check .
	mypy remediations/ notifier/
	$(TF) fmt -check -recursive
	trivy config infra --severity HIGH,CRITICAL --exit-code 1
	checkov -d infra --quiet --compact

fmt: ## apply formatting
	ruff format .
	ruff check --fix .
	$(TF) fmt -recursive

coverage: ## fail if any detection is missing a piece of its unit
	./scripts/check-detection-coverage.sh

validate: build ## terraform validate — works without credentials
	$(TF) init -backend=false -input=false
	$(TF) validate

plan: build ## terraform plan — needs credentials
	$(TF) init -input=false
	$(TF) plan

deploy: build ## deploy detections + remediations
	$(TF) init -input=false
	$(TF) apply

destroy:
	$(TF) destroy

attack: ## live technique execution — ISOLATED ACCOUNT ONLY: make attack TTP=aws.exfiltration.s3-backdoor
	@echo "target account: $$(aws sts get-caller-identity --query Account --output text)"
	@read -p "confirm this is the isolated lab account [y/N] " ok && [ "$$ok" = "y" ]
	stratus detonate $(TTP)
	./attack-sim/assert.sh $(TTP)
	stratus cleanup $(TTP)

timing: ## measure detection + remediation latency per detection
	./attack-sim/measure.sh > docs/evidence/time-to-remediate.md

evidence: timing ## regenerate evidence artifacts

clean:
	rm -rf build
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + ; rm -rf .pytest_cache .mypy_cache .ruff_cache
