"""Remediation handlers, one package per detection.

Directory names under ``detections/`` are kebab-case (``s3-public``) because
that is the detection ID used in alerts, IAM, and Terraform. Python packages
here are the snake_case form of the same ID (``s3_public``). The mapping is
mechanical and is enforced by ``scripts/check-detection-coverage.sh``.
"""
