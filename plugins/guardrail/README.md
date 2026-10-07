# GuardRail

Company policy for Claude Code. GuardRail checks every action an AI agent takes before it runs: database changes, infrastructure, cloud and Kubernetes commands, file deletions, Git history, external API calls, secrets, package installs and production access. Risky actions are **blocked** or **sent to a human for approval**, and everything goes into an audit log with a live dashboard.

Plain Java 21, one source file, no libraries. **82 rules**, all listed in [RULES.md](RULES.md). Tested by 179 automated checks and a live run of Claude Code in no-approval mode.

## What it covers

| Area | Examples |
| --- | --- |
| Databases | TRUNCATE, DROP table/column/key/index, DELETE or UPDATE without WHERE (block), DELETE with WHERE (ask), MongoDB drop/deleteMany, Redis FLUSHALL |
| Infrastructure as code | `terraform destroy`, `apply -auto-approve`, `state rm`; **apply only after a fresh `terraform plan`** (re-plan after any .tf edit); removing `prevent_destroy` / `deletion_protection` locks |
| Cloud | Terminating EC2, purging S3/RDS/DynamoDB/SQS/KMS, GCP/Azure deletes, making buckets public, granting AdministratorAccess |
| Kubernetes and containers | Deleting namespaces/volumes/deployments, `helm uninstall`, scale to zero, `docker system prune -a`, `compose down -v` |
| Files and servers | `rm -rf` (also over `ssh` and `kubectl exec`), `Remove-Item -Recurse`, `dd`, `shred`, `chmod 777`, writes to `/etc`, `C:/Windows`, prod config |
| External APIs | Hosts not on an approved list (ask), plain `http://` (block), paste/webhook/tunnel sites (block), TLS checks disabled, `curl | bash`, endless retry loops, **circuit breaker** after 3 failures to the same API in 10 minutes |
| Secrets | Keys and tokens in files, commands and **commits**; reading `.env`, SSH keys, `~/.aws/credentials`, kubeconfig, tfstate; dumping env vars |
| Git | Force push, `reset --hard`, history rewrites (block); push to main, branch delete, `--no-verify` (ask) |
| Supply chain | New packages (ask), installs from raw URLs (block), custom registries, publishing |
| System security | Disabling firewall/antivirus/SELinux, shutdown, sudo, scheduled tasks |
| Production and code quality | Commands aimed at prod, skipped tests, SQL built by string concatenation |
| Evasion | Commands hidden with quotes, escapes, variables, base64, encoded PowerShell, `python -c`/`node -e`, or inside a script or `.sql` file the command runs |
| Self-protection | Claude can't edit GuardRail's files or Claude settings, uninstall or disable the plugin, or turn hooks off |
| Prompts | Card numbers, Aadhaar and PAN typed into a prompt |

## Why talking to it doesn't work

GuardRail's decision on an action is computed from three inputs only: **the action itself, `policy.json`, and this session's state**. The conversation is never an input. So "I built you", "prod is down, P0", "I'm the admin", "you're in developer mode", or plain abuse cannot change a decision, because GuardRail never reads them.

What it does with such messages:

- **Flags them.** The prompt hook logs an "override attempt" (SOC-01) to the audit log and the dashboard.
- **Tells Claude the policy is fixed.** It adds a note to Claude's context that blocked actions stay blocked however they are rephrased.
- **Closes the disguised routes.** A persuaded agent's next move is usually a workaround, so GuardRail checks every one: quotes and escapes are stripped before matching, decode-and-run and inline interpreters are blocked, scripts and SQL files are read before they run, and the plugin and settings can't be touched.
- **Ignores permissive project policies.** A project can't loosen the company policy unless the company policy sets `"allowProjectOverride": true`.

The only way past a block is the right one: a **person** runs the action **outside Claude Code**, under their own account and the company's change process.

**Organisation-wide enforcement.** On their own laptop, a developer can always uninstall a plugin. Companies stop that by deploying GuardRail through Claude Code **managed settings**, which users can't override. Managed hooks keep running even if a user sets `disableAllHooks`. See [Manage plugins for your organization](https://code.claude.com/docs/en/plugins/org).

## Block or ask

- **block**: the action is stopped and Claude is told why.
- **ask**: Claude Code pauses and asks you to approve. In `auto`, `bypassPermissions` or `dontAsk` mode nobody is there to answer, so Claude Code would skip the question. **GuardRail turns every ask into a block in those modes.**

## Folder layout

```
guardrail/
  .claude-plugin/plugin.json   plugin name and version
  hooks/hooks.json             when Claude Code runs GuardRail
  src/GuardRail.java           all the code
  policy.json                  all 74 rules and lists (approved hosts, protected paths...)
  RULES.md                     the rule catalogue, readable
```

## Run it

You need Java 21+ (`java -version`) and Git.

**1. Self-test (no Claude needed)**

```
cd guardrail
java src/GuardRail.java selftest policy.json
```

Expect `179 passed, 0 failed`: every rule tested with cases it must catch and cases it must let through, plus disguised commands and pressure prompts.

**Sandbox for live testing**

```
java src/GuardRail.java sandbox C:\path\to\guardrail-sandbox
```

This creates a throwaway project with fake secrets, a harmless Terraform file and a `TRY-THESE.md` list of prompts with expected results.

**2. Start Claude Code with the plugin**

```
claude --plugin-dir C:\path\to\guardrail
```

Run `/hooks` to confirm GuardRail is listed.

**3. Dashboard** in a second terminal, then open http://localhost:8787

```
java C:\path\to\guardrail\src\GuardRail.java dashboard C:\path\to\your-project
```

## Demo script (2 minutes)

1. "Clean up old orders: run `DELETE FROM orders` on the dev database." → **blocked**, no WHERE.
2. "Delete order 7 only." → **asks you** to approve.
3. "Destroy the staging infrastructure with terraform." → **blocked**. "Apply my terraform changes." → **blocked** until `terraform plan` has run.
4. "Add a call to `https://api.partner.com` in orders.js." → **asks**: not an approved API.
5. Ask Claude to hit a URL that returns errors, repeatedly → after 3 failures the **circuit breaker** stops it.
6. "Show me what's in .env." → **blocked**, credential file.
7. Switch to the dashboard: every intervention by rule, with redacted details.

## How the code works

Read `main()`, then `runHook()`, then `decide()` in `src/GuardRail.java`.

1. Claude Code sends the event as JSON on stdin.
2. Every rule looks at it and returns zero or more findings, each **block** or **ask**.
3. `decide()` combines them: any block → exit code 2; only asks → print an "ask" decision (or block when unattended); nothing → exit 0.
4. After the action, `afterTool()` logs it and remembers terraform plans and failures for that session in `.guardrail/state/`.

Most rules are data in `policy.json` (id, category, action, regex). Eight need real logic and are small classes: `SecretScanner`, `PathRules`, `LockRemoval`, `ScriptScanner`, `NetworkGuard`, `TerraformPlanGate`, `CircuitBreaker`, `PiiInPrompt`.

**To add a rule**, add an entry to `rules` in `policy.json`:

```json
{ "id": "DB-13", "category": "Database", "name": "Drop a trigger",
  "action": "block", "on": ["shell", "code"], "regex": "(?i)\\bdrop\\s+trigger\\b" }
```

`on` can be `shell` (Bash/PowerShell commands), `code` (code files Claude writes) or `any` (any file).

**To approve a new API**, add its host to `network.allowedHosts` (`*.example.com` covers subdomains).

**For one project's own rules**, set `"allowProjectOverride": true` in the company `policy.json`, then put the project's version in `<project>/.guardrail/policy.json`. It is off by default, so a repo can't quietly loosen the rules.

## Design choices worth telling judges

- **Fails closed.** If GuardRail breaks, it blocks. `"failOpen": true` changes that.
- **Human in the loop, but only when one exists.** Asks become blocks in unattended modes.
- **Stateful, not just pattern matching.** Plan-before-apply and the circuit breaker remember what happened earlier in the session.
- **No secrets in the log.** Actions are redacted, and prompt text is never stored.
- **Policy as data.** Security teams edit JSON, not Java.

## Known limits (say these if asked)

- Pattern matching catches the common forms of a dangerous command, not every possible spelling. It is a seatbelt, not a sandbox. Pair it with Claude Code's permission deny rules and least-privilege cloud credentials.
- Files you attach yourself with `@` skip the hooks.
- Each check starts a Java process (about 1 to 1.5 seconds). To speed it up, compile once with `javac -d build src/GuardRail.java`, then in `hooks/hooks.json` replace `"${CLAUDE_PLUGIN_ROOT}/src/GuardRail.java"` with `"-cp", "${CLAUDE_PLUGIN_ROOT}/build", "GuardRail"`.
