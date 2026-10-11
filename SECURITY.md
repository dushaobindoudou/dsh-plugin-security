# Security policy

## Supported versions

Security fixes land on the latest `0.x` release. Upgrade with `dsh plugin --profile <name> add dsh-plugin-security@latest` and restart dsh.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through [GitHub private vulnerability reporting](https://github.com/dushaobindoudou/dsh-plugin-security/security/advisories/new). Do not open a public issue for:

- a way for a plugin to run a tool without passing the call gate, or to evade attribution;
- a way to disable, uninstall or whitelist plugins without the user's action;
- a way to make the scanner execute target plugin code, or to leak source or local paths off the machine;
- a prompt-injection path that turns reviewed plugin text into instructions for the reviewing agent.

Include the dsh and plugin versions, a minimal reproduction, and redacted evidence. You will get an acknowledgement within 7 days and a fix or mitigation plan within 30 days for confirmed issues.

False positives and ordinary bugs without sensitive material belong in [issues](https://github.com/dushaobindoudou/dsh-plugin-security/issues/new/choose).

## Scope and limits

This plugin is a post-load check, not a sandbox: it shares the host process with the plugins it checks, and only tool calls pass through the call gate. See the README's "Privacy and limits" section before reporting behavior that follows from those limits.
