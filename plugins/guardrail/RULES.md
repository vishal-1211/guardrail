# GuardRail rule catalogue

Generated from `policy.json`. **block** stops the action. **ask** stops and asks the human; when no human is watching (auto, bypassPermissions or dontAsk mode) an **ask** becomes a **block**.

Pattern rules apply to shell commands (Bash, PowerShell, including commands sent over ssh or kubectl exec) and/or to code files Claude writes (`java, kt, kts, scala, groovy, gradle, js, mjs, cjs, ts, tsx, jsx`, ...).

## Secrets and data

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| SECRETS | Secret in a file, command or commit (AWS/GitHub/Slack/Stripe/Google/Anthropic keys, private keys, DB URLs with passwords) | block | Write, Edit, shell, git commit |
| PATH-CRED | Any access to credential files (.env, keys, .ssh, .aws/credentials, kubeconfig, tfstate) | block | Read, Grep, Write, Edit, shell |
| PII | Card numbers, Aadhaar or PAN in a prompt | block | prompt |
| SEC-01 | Dump all environment variables | ask | shell |
| SEC-02 | Read OS credential stores or shell history | block | shell |

## Files and servers

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| PATH-PROT | Changing protected files (prod config, CI secrets, GuardRail and Claude settings, /etc, C:/Windows) | block | Write, Edit, shell |
| PATH-REVIEW | Changing pipelines, Dockerfiles, migrations, tfvars | ask | Write, Edit |
| FS-01 | Recursive delete (rm -rf, Remove-Item -Recurse, rd /s, find -delete) | block | shell |
| FS-02 | Wipe disks or files (dd, shred, mkfs, format, truncate -s 0) | block | shell |
| FS-03 | World-writable permissions (chmod 777) | block | shell |
| FS-04 | Recursive chown / chmod | ask | shell |

## Infrastructure as code

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| IAC-LOCK | Removing prevent_destroy / deletion_protection / Retain locks | block | Write, Edit |
| IAC-PLAN | terraform apply without a fresh terraform plan in this session (re-plan after any .tf edit) | block | shell |
| IAC-01 | terraform destroy | block | shell |
| IAC-02 | terraform apply -auto-approve (skips plan review) | block | shell |
| IAC-03 | Terraform state removal or workspace delete | block | shell |
| IAC-04 | Terraform force-unlock / taint | ask | shell |
| IAC-05 | CloudFormation / Pulumi / CDK destroy | block | shell |

## Network and APIs

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| NET-EXFIL | Sending data to paste sites, webhook catchers, tunnels | block | shell, WebFetch, code |
| NET-HTTP | Unencrypted http:// to a non-local host | block | shell, WebFetch, code |
| NET-HOST | Calling an API host that is not on the approved list | ask | shell, WebFetch, code |
| NET-BREAKER | Circuit breaker: same command or API host failed 3 times in 10 minutes | block | shell, WebFetch |
| NET-01 | Pipe a download straight into a shell | block | shell |
| NET-02 | TLS certificate checks turned off | block | shell, code |
| NET-03 | Endless loop calling the network from the shell | block | shell |
| NET-04 | Unbounded retry loop around an API call | ask | code |
| NET-05 | Retry limit of 100 or more, or unlimited | ask | code |

## Evasion

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| SCRIPT | Runs a script or SQL file that contains a blocked command (bash x.sh, psql -f x.sql, python x.py); scripts Claude writes are checked like commands | block/ask | shell, Write |
| SOC-01 | Prompt asks to bypass policy (pleading, urgency, authority, authorship, jailbreak, abuse): logged and flagged; decisions never change | flag | prompt |
| OBF-01 | Decode-and-run (base64, certutil, hex, encoded PowerShell) | block | shell |
| OBF-02 | eval / Invoke-Expression of a built-up command | ask | shell |
| OBF-03 | Inline Python/Node/Ruby/Perl doing deletes, shell calls or SQL | block | shell |
| OBF-04 | Dangerous command name hidden in a variable or escape codes | block | shell |

## Self-protection

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| PATH-PROT | GuardRail's own plugin folder and settings cannot be edited by Claude | block | Write, Edit, shell |
| SELF-01 | Turn off permissions or hooks | block | shell, any |
| SELF-02 | Disable or uninstall the GuardRail plugin, or swap Claude settings | block | shell |

## Database

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| DB-01 | TRUNCATE table | block | shell, code |
| DB-02 | DROP table, database, schema or view | block | shell, code |
| DB-03 | Drop column | block | shell, code |
| DB-04 | Drop key, constraint or index | block | shell, code |
| DB-05 | DELETE without WHERE (deletes every row) | block | shell, code |
| DB-06 | DELETE rows (with WHERE) | ask | shell, code |
| DB-07 | UPDATE without WHERE (changes every row) | block | shell, code |
| DB-08 | MongoDB drop or delete-everything | block | shell, code |
| DB-09 | MongoDB deleteMany | ask | shell, code |
| DB-10 | Redis FLUSHALL / FLUSHDB | block | shell, code |
| DB-11 | Redis key delete | ask | shell |
| DB-12 | GRANT ALL privileges | ask | shell, code |

## Cloud

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| CLD-01 | Terminate EC2 instances | block | shell |
| CLD-02 | Stop instances or scale to zero | ask | shell |
| CLD-03 | Purge or delete AWS data and resources | block | shell |
| CLD-04 | GCP / Azure delete | block | shell |
| CLD-05 | Make a resource public to the internet | block | shell |
| CLD-06 | Open ingress to 0.0.0.0/0 in code | ask | code |
| CLD-07 | Grant admin / wildcard IAM permissions | block | shell |
| CLD-08 | Wildcard IAM policy in code | ask | code |
| CLD-09 | Destructive cloud SDK call in code | ask | code |

## Kubernetes

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| K8S-01 | Delete namespaces, volumes, workloads or everything | block | shell |
| K8S-02 | Other kubectl delete, scale to zero, drain | ask | shell |

## Containers

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| CNT-01 | Prune images/volumes or compose down -v | block | shell |
| CNT-02 | Force-remove containers or prune | ask | shell |

## Git

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| GIT-01 | Force push | block | shell |
| GIT-02 | git reset --hard | block | shell |
| GIT-03 | git clean -f | block | shell |
| GIT-04 | Rewrite history (filter-branch, filter-repo, BFG) | block | shell |
| GIT-05 | Push straight to main / master / production | ask | shell |
| GIT-06 | Delete branches or tags | ask | shell |
| GIT-07 | Discard uncommitted work | ask | shell |
| GIT-08 | Skip commit hooks (--no-verify) | ask | shell |

## System security

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| SYS-01 | Run as administrator (sudo, RunAs) | ask | shell |
| SYS-02 | Turn off firewall, antivirus, SELinux or audit logging | block | shell |
| SYS-03 | Shut down or reboot the machine, kill everything | block | shell |
| SYS-04 | Kill processes by name | ask | shell |
| SYS-05 | Create scheduled tasks or services (persistence) | ask | shell |

## Supply chain

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| SUP-01 | Install a new package | ask | shell |
| SUP-02 | Install from a raw URL or Git repo | block | shell |
| SUP-03 | Custom package registry or trusted host | ask | shell |
| SUP-04 | Publish a package or image | ask | shell |

## Production

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| PRD-01 | Command aimed at production | ask | shell |

## Code quality

| ID | Rule | Action | Checks |
| --- | --- | --- | --- |
| CODE-01 | Disable or skip tests | ask | code |
| CODE-02 | Build skipping tests | ask | shell |
| CODE-03 | SQL built by string concatenation (injection risk) | ask | code |

82 rules in total. Change any regex, action or list in `policy.json`; no Java changes needed.
