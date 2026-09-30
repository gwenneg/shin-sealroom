# Security policy

Sealroom runs untrusted code next to your credentials, so a flaw in it matters. Thank you for reporting one.

## Reporting a vulnerability

Report it privately, through GitHub's [private vulnerability reporting](../../security/advisories/new), from the repository's Security tab. Do not open a public issue.

Include what you did, what happened, and what you expected, with the versions of Sealroom, Podman or Docker, and your operating system.

## What to expect

Sealroom is a personal open source project, maintained on a best-effort basis. There is no guaranteed response time and no bounty. Reports are read, answered, and fixed in the order of their severity, and a fix is disclosed in a GitHub security advisory once released, with credit to the reporter unless they ask otherwise.

Only the latest version on `main` is supported.

Sealroom has not had an independent security review. Before a 1.0 release, its proxy goes through adversarial red-teaming, fuzzing, differential testing and, if a reviewer can be found, an independent review: see [Before 1.0](docs/proxy.md#before-10).

## In scope

Anything that breaks what the [threat model](docs/threat-model.md) says Sealroom defends against, for example:

- code in the agent container reaching the host, its files, or anything the proxy should refuse;
- a credential of the user's becoming readable in the agent container, or usable beyond what the proxy's rules allow;
- a request carrying the plugin's own credential getting through the proxy;
- the launcher running code, or writing outside the run directory, because of what the agent container wrote;
- a way to widen the proxy's rules or the containers' restrictions from inside the run.

## Out of scope

The limits the threat model names, such as the model channel, the content of a pull request the user approves, and a kernel exploit, unless Sealroom makes them worse than described. Flaws in Podman, Docker, Go or Claude Code themselves belong to those projects; tell them, and tell Sealroom too if Sealroom can mitigate the flaw.
