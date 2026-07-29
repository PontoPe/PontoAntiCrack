"""Slack alerting for PontoAntiCrack.

Kept out of ``remediations`` so that "what we did" and "who we told" stay
separable: a remediation must not depend on an alert being deliverable, and an
alerting change must not be able to break a remediation.
"""
