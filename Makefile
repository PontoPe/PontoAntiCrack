SHELL := /bin/bash
PY := python3

.PHONY: help install test lint deploy destroy attack timing evidence clean

help: ## show targets
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t -s $$'\t'

install: ## dev dependencies
	$(PY) -m pip install -r requirements-dev.txt

test: ## unit tests — fixtures + moto, no AWS account needed
	pytest tests/ -v

lint: ## ruff + mypy + terraform static analysis
	ruff check .
	mypy remediations/ notifier/
	cd infra && terraform fmt -check -recursive && tfsec . && checkov -d . --quiet

deploy: ## deploy detections + remediations
	cd infra && terraform init && terraform apply

destroy:
	cd infra && terraform destroy

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
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + ; rm -rf .pytest_cache .mypy_cache
