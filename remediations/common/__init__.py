"""Shared runtime for every remediation Lambda.

The point of this package is that the invariants the threat model depends on —
snapshot before change, tag exclusion, circuit breaker, dry-run — are enforced
by :mod:`remediations.common.runtime` and not by each handler remembering to do
them. A handler only decides *whether* a resource is actually dangerous and
*what* the minimal fix is.
"""
