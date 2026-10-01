# Proxies considered

Sealroom builds its own proxy. This document records what was considered instead, what each option does well, and why none was chosen. It reflects the state of each project at the end of September 2026, from their documentation, their source code and their published advisories; these projects move fast, and a later review may conclude differently.

## What Sealroom needs

The proxy stands between a plugin that may be hostile and the user's credentials. It must:

1. refuse everything but exact host, method and path rules, including a request whose path, host or headers can be read two ways;
2. hold the credentials itself, add them only to matching requests, and refuse any request that carries a credential of its own;
3. mint Google access tokens from a user's `gcloud` login, for Claude on Vertex AI;
4. run locally, in a container, with Podman or Docker;
5. be maintained, trustworthy, and small enough to review.

Most options below are good at what they were built for. The gap is that few were built for this: egress, with the client as the attacker, and the proxy holding the secrets.

## Egress proxies with credential injection

### iron-proxy

[github.com/paradigmxyz/iron-proxy](https://github.com/paradigmxyz/iron-proxy), Go, Apache-2.0. An egress firewall for untrusted workloads, with TLS interception, a built-in DNS server, rules on host, method and path, credential injection and replacement, Google token minting, and JSON audit logs. Sealroom used it, built from a verified commit, before replacing it.

What it does well: its design matches Sealroom's closely, it checks addresses as each connection is made, refuses dot segments before any rule, never follows redirects, and is used by other agent projects.

Why it was replaced:

- **A credential can be sent in cleartext.** Its credential rules match host, method and path but not the scheme, and it listens for plain HTTP: a request to `http://api.anthropic.com` gets the real credential swapped in and sent unencrypted.
- **Rules ignore the port**, while the connection keeps the port the client asked for.
- **Credentials are swapped by substring**, optionally in bodies, queries and paths, which can write a real credential where the client reads it back.
- **Large bodies are truncated silently** when a transform reads them, so the upstream receives a corrupted request.
- **Google tokens likely stop refreshing after an hour**: the token source keeps the context of the first request. This was read in the code, not tested.
- **Its main listeners set no timeouts**, and its default address deny list leaves out private ranges.
- **The project**: about six months old, written mostly by one person, its releases unsigned since v0.42.0, and moved into the GitHub organization of an investment firm without a public explanation. About 16,500 lines of Go and 155 modules in its dependency tree, most of it for features Sealroom does not use.

### agentgateway

[github.com/agentgateway/agentgateway](https://github.com/agentgateway/agentgateway), Rust, Apache-2.0, a Linux Foundation project led by Solo.io. A gateway for AI traffic with an egress proxy mode, certificates minted on the fly, per-route credential injection, Google credentials including user logins, and authorization rules written in CEL.

What it does well: strong governance, many contributors, a security process with advisories, cosign-signed images with build provenance, and most of Sealroom's needs built in.

Why it was not chosen:

- **Paths are matched as sent, without normalization**, so `/allowed/../other` matches a rule for `/allowed`. The issue is [open](https://github.com/agentgateway/agentgateway/issues/1023). Closing it would mean writing the path checks as CEL rules in Sealroom's configuration.
- **Misconfiguration is not a vulnerability** under its security policy, and its configuration surface is very large: the security of a generated configuration would rest on Sealroom alone.
- **No refusal of private or metadata addresses** after resolution.
- **No header allowlist**, only removal by name.
- **The egress mode is young**: it reached a stable release in August 2026.

## General-purpose proxies

### Envoy

[envoyproxy.io](https://www.envoyproxy.io), C++, a CNCF graduated project. The most widely deployed and scrutinized proxy considered, with mature path normalization options, authorization rules, header manipulation and a credential injector.

What it does well: maturity, governance, a long security history, and HTTP handling that has withstood a decade of attacks.

Why it was not chosen:

- **No header allowlist**: only removal by name, unless a Lua script is added.
- **No Google user logins**: its credential injector supports static secrets and the OAuth client-credentials flow, so Vertex would need a sidecar to refresh tokens.
- **No certificates minted on the fly**: they would be minted ahead of each run for each allowed host.
- **A configuration that is itself security code**: listeners, clusters, authorization, scripts and credential injection, with defaults that are unsafe for path-based rules, path normalization being off by default. Its own CVE history (for example CVE-2021-29492 and CVE-2026-73553) shows how subtle path rules are, even in expert hands.
- **Size**: a binary of roughly 60 to 100 MB, impractical to build from source in Sealroom's pipeline.

Envoy remains the strongest external option if Sealroom ever stops maintaining its own proxy.

### mitmproxy

[mitmproxy.org](https://mitmproxy.org), Python. A mature interception proxy, scriptable with add-ons.

Why it was not chosen: it is a debugging and analysis tool, not a security boundary. The rules and credential handling would all be Sealroom's own Python code, so it offers little over writing the proxy, with a Python runtime and caveats on streaming responses.

### Squid and Smokescreen

[squid-cache.org](https://www.squid-cache.org) and [github.com/stripe/smokescreen](https://github.com/stripe/smokescreen). Egress proxies that filter by destination.

Why they were not chosen: neither intercepts TLS to add credentials, so they cannot keep credentials out of the agent's container. Their advisories, on request smuggling in Squid and on host names with a trailing dot, capitals or brackets in Smokescreen, informed Sealroom's checks.

## Sandboxes for agents

These isolate an agent and some include a credential proxy, but their proxy is part of a sandbox rather than a component Sealroom could run on its own:

- **Anthropic's sandbox-runtime** ([github.com/anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)), in beta: rules by domain, with path and method checks left to a callback, credential placeholders replaced in every header and the body, and no refusal of a credential the agent brings. Two of its advisories, an empty allow list meaning "allow all" (CVE-2025-66479) and a host name truncated at a null byte, shaped Sealroom's rules.
- **Docker Sandboxes** ([docs.docker.com/ai/sandboxes](https://docs.docker.com/ai/sandboxes/)): micro-VMs with credentials injected from the host's keychain, but rules by domain only, tied to Docker Desktop, and closed source.
- **Gondolin, Matchlock, nono, Leash, nilbox, microsandbox**: each contributed ideas, Gondolin's refusal of a placeholder sent to the wrong host, nono's refusal of an agent's own credential, microsandbox's check that the host matches the TLS name, but each is tied to its own sandbox, and several leave the request's host unchecked against the TLS server name.

## Gateways for model traffic

**LiteLLM, Portkey, Tailscale Aperture** handle model traffic and some mint Google tokens, but they cover only the model, not GitHub or anything else the agent reaches, and so could only be one more component next to a proxy. LiteLLM's package was also compromised on PyPI in March 2026.

## Hosted services

**Vercel Sandbox's firewall, Cloudflare's sandbox outbound workers, the GitHub Copilot coding agent's firewall, OpenAI Codex's internet access, and Claude Code's cloud sessions** run on their providers' infrastructure, not on the user's machine. Their documentation contributed lessons: Vercel's firewall filters on the TLS server name without checking the host the request names, and its matchers never block; Claude Code's cloud sessions scope git credentials to one repository and branch.

## The decision

None of these fits all five needs above. The closest external options trade one weakness for another: iron-proxy's design for its project and its flaws, agentgateway's governance for path matching left to Sealroom, Envoy's maturity for a configuration as subtle as code. Sealroom's own proxy takes the best idea from each, is strict where they normalize, and stays small enough to review: see [the proxy](proxy.md).
