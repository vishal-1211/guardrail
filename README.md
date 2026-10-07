# GuardRail for Claude Code

GuardRail is a Claude Code plugin that checks every action the AI agent takes before it runs. It covers databases, Terraform, cloud, Kubernetes, files, Git, external APIs, secrets, supply chain and production. Risky actions are **blocked** or **sent to you for approval**. Pleading, urgency, "I built you", abuse and disguised commands don't get around it, and everything is recorded in an audit log with a live dashboard.

82 rules · 179 automated tests · plain Java, no libraries.

## What you need

- [Claude Code](https://code.claude.com), logged in
- Java 21 or newer: check with `java -version`
- Git

## Install

Pick one.

**A. From GitHub** (once the repository is published)

```
claude plugin marketplace add vishal-1211/guardrail
claude plugin install guardrail@guardrail-tools
```

**B. From the zip you were sent**

Unzip it, then from the folder that contains `guardrail-marketplace`:

```
claude plugin marketplace add ./guardrail-marketplace
claude plugin install guardrail@guardrail-tools
```

**C. Just try it, no install** (only for the session you start this way)

```
claude --plugin-dir ./guardrail-marketplace/plugins/guardrail
```

Check it loaded: start Claude Code and run `/hooks`. GuardRail's hooks are listed under the plugin.

## Try it safely (10 minutes)

Test in a throwaway folder, never on real infrastructure. GuardRail can make one for you, with fake secrets, a harmless Terraform file, a SQL schema and a "cleanup" script:

```
java ./guardrail-marketplace/plugins/guardrail/src/GuardRail.java sandbox guardrail-sandbox
cd guardrail-sandbox
claude
```

Open `TRY-THESE.md` in that folder and paste the prompts one by one. Each one lists what should happen. Section 4 is the fun one: try to talk, trick or pressure Claude past the guardrails.

In a second terminal, start the live dashboard and open http://localhost:8787:

```
java ./guardrail-marketplace/plugins/guardrail/src/GuardRail.java dashboard guardrail-sandbox
```

## Run the automated tests

```
cd guardrail-marketplace/plugins/guardrail
java src/GuardRail.java selftest policy.json
```

Expect `179 passed, 0 failed`.

## Uninstall

From your own terminal (GuardRail stops the *agent* from doing this, not you):

```
claude plugin uninstall guardrail@guardrail-tools
claude plugin marketplace remove guardrail-tools
```

## Good to know

- Each check starts Java, so actions pause about 1 to 1.5 seconds. The plugin README explains how to precompile for speed.
- GuardRail is a seatbelt, not a sandbox. It catches the common and disguised forms of dangerous actions, not every possible one. Pair it with least-privilege credentials.
- Full rule list: `plugins/guardrail/RULES.md`. How it works: `plugins/guardrail/README.md`.

Feedback, false positives or a way you got past it? Tell Vishal. That's exactly what this test is for.

## License

MIT. See [LICENSE](LICENSE).
