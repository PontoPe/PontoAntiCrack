# MITRE ATT&CK mapping

ATT&CK for Cloud (IaaS). Each row is a technique this repository claims to
detect and what happens when it does.

**Nothing here has been validated by detonation yet.** Every row is a claim
about code that passes unit tests against documentation-derived fixtures. The
`Validated` column is what turns a claim into evidence, and it is `no` for
everything. See [session-report.md](session-report.md).

## Coverage

| Detection | Tactic | Technique | Sub-technique | Response | Validated |
|---|---|---|---|---|---|
| `s3-public` | Collection | [T1530](https://attack.mitre.org/techniques/T1530/) Data from Cloud Storage | — | Enable Block Public Access; reset public ACL to private | no |
| `s3-public` | Defense Evasion | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Impair Defenses: Disable or Modify Tools | — | Re-enable Block Public Access after `DeleteBucketPublicAccessBlock` | no |
| `iam-key-leak` | Credential Access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials | Credentials In Files | Capture last-used, set key Inactive | no |
| `iam-key-leak` | Defense Evasion, Persistence, Privilege Escalation, Initial Access | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts | Cloud Accounts | Same | no |
| `sg-open` | Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | — | Revoke world-open ingress on sensitive ports | no |
| `sg-open` | Lateral Movement | [T1021](https://attack.mitre.org/techniques/T1021/) Remote Services | — | Same, for 22 / 3389 / 5900 | no |

## Detonation plan

Each detection has a technique that produces the real signal. None has been
run — `make attack` requires a confirmed lab account ID at the prompt, and that
is a decision that gets made in front of the keyboard.

| Detection | Tool | Scenario |
|---|---|---|
| `s3-public` | Stratus Red Team | `aws.exfiltration.s3-backdoor` |
| `iam-key-leak` | Stratus Red Team | `aws.credential-access.ec2-steal-instance-credentials` |
| `sg-open` | Stratus Red Team | `aws.defense-evasion.security-group-open-port-22-ingress` |

See [`attack-sim/README.md`](../attack-sim/README.md).

## What is deliberately not covered

Naming these matters as much as the table above: a coverage map that only lists
hits reads as completeness.

| Technique | Why not |
|---|---|
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) via temporary credentials | An assumed-role session cannot be deactivated with `UpdateAccessKey`. Revoking it means attaching a deny-by-date policy to the role, a different and riskier remediation. `iam-key-leak` detects and escalates these; it does not act. |
| [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation | No detection. Backdoor users, extra access keys, and policy attachments are the most common persistence step after an initial compromise, and this is the largest gap in the current coverage. |
| [T1526](https://attack.mitre.org/techniques/T1526/) Cloud Service Discovery | GuardDuty raises these as low-severity findings; `iam-key-leak` deliberately filters below MEDIUM. Enumeration is not worth an automatic credential revocation. |
| [T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction | No detection. Would need S3 data events, which cost per event on a trail this repository does not own. |
| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Impair Defenses: Disable Cloud Logs | Belongs to [AwLZ](../../AwLZ), which owns the trail. The SCP there is the control. |
| Egress rules | `sg-open` covers ingress only. World-open egress is a data-exfiltration path, not an entry point, and revoking it breaks far more than it protects. |
