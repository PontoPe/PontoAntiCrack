#!/usr/bin/env bash
# Stage the Lambda deployment package.
#
# One artifact for all three detections: remediations/ and notifier/, nothing
# else. No third-party dependencies — everything the handlers use is either in
# the standard library or is boto3 as shipped by the AWS Python runtime. That is
# a deliberate constraint, not an accident: a deployment package with no
# vendored wheels has no supply chain to review before each deploy.
#
# Terraform zips the result. Run this before `terraform plan` or `apply`.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="${root}/build/lambda"

rm -rf "${build}"
mkdir -p "${build}"

for package in remediations notifier; do
  cp -r "${root}/${package}" "${build}/${package}"
done

# Compiled artefacts change on every machine and would churn the source hash,
# redeploying identical code.
find "${build}" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "${build}" -name '*.py[co]' -delete

# Documentation and IAM policy templates are build-time inputs, not runtime
# ones. Terraform reads policy.json directly from the source tree; shipping a
# second copy inside the function invites the two to drift.
find "${build}" \( -name '*.md' -o -name 'policy.json' \) -delete

# A syntax error is much cheaper to find here than in a cold start at 3am.
python -m compileall -q "${build}" > /dev/null
find "${build}" -name '__pycache__' -type d -prune -exec rm -rf {} +

printf 'staged %s (%s files)\n' "${build}" "$(find "${build}" -type f | wc -l | tr -d ' ')"
