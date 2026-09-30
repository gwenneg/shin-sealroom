# The proxy

The proxy is the agent's only way out, and it holds the user's credentials. This document is its specification: what it does, what it refuses, and why. Each rule comes from a weakness found in another proxy, gateway or agent sandbox, cited in the sources at the end.

Sealroom builds its own proxy, in `internal/egress`, run as `sealroom proxy` in its container, rather than depending on one. [Proxies considered](proxy-alternatives.md) records the options weighed, iron-proxy, which Sealroom used before, agentgateway, Envoy and others, and why none was chosen. In short, a small proxy that does exactly what Sealroom needs, strictly, is easier to trust and to review.

## The principle

Nearly every bypass of a proxy comes from a difference in reading: the proxy decides on one view of a request, a decoded path, merged headers, the TLS server name, a resolved address, and forwards another. Sealroom's proxy accepts one exact form of every input, decides on those bytes, and forwards the same bytes on a request it builds itself. Anything unusual is refused, never fixed. Claude Code, git and the GitHub CLI only ever send ordinary requests, so the strictness costs nothing.

## What it does

### Scope

- Only the traffic the rules allow is carried. A configuration with no rule allows nothing, and any error refuses.
- HTTPS on port 443 only, toward the agent and toward the internet. There is no plain HTTP listener, and no port ever comes from a request.
- HTTP/1.1 only toward the agent: Claude Code offers nothing else, and git and the GitHub CLI fall back to it. This removes the HTTP/2 attacks proxies have suffered.

### DNS

- An allowed name resolves to the proxy, as an IPv4 address only. Any other name does not exist.
- No query is ever forwarded, so DNS carries nothing out.

### TLS toward the agent

- A certificate is minted only for an exact allowed name, from the run's CA, never for a wildcard. The handshake is refused for a missing name, an address, a trailing dot, a name not in lowercase, a punycode label, or any name no rule allows, before any HTTP is read, and the refusal is logged.
- Session resumption is off, so every handshake goes through that check: a session made for an allowed name cannot be resumed under another.

### Refusing before any rule

The proxy reads the agent's raw bytes itself before Go's HTTP parser does, because that parser is lenient: it accepts bare LF line endings and folded headers, merges a repeated `Content-Length`, drops one sent with chunked framing, and ignores chunk extensions and trailers, all before any check could see them. Only bytes already in RFC 9112's strict form reach it. A refused request head is answered in order, with its reason, and the connection closes. A body whose chunked framing breaks is cut before its end, so the upstream never receives it whole.

A request is refused, and never forwarded, when:

- its target is not in origin form (`/path?query`): no absolute URI, no `*`, no `CONNECT`;
- its raw path is not canonical: it must start with `/` and hold only letters, digits and `-._~:@`, with no empty segment, no `.` or `..` segment, and so no percent-encoding, `;`, `\`, `#` or control byte;
- its query is not `name=value` pairs of letters, digits, `-._~` and well-formed escapes of any byte but a control byte or DEL;
- its `Host` is not exactly the TLS server name, with no port but 443;
- a header appears twice, has a name outside letters, digits and dashes, or a value outside visible ASCII;
- it asks for an `Upgrade`, a non-empty `Expect`, or names headers in `Connection`;
- a line ends with anything but CRLF, or a header is folded onto the next line;
- its request line is not `METHOD SP TARGET SP HTTP/1.1`, with a method of upper-case letters;
- it has no `Host`, or more than one;
- its framing is not plain: `Content-Length` and `Transfer-Encoding` together or repeated, a length with a sign or a leading zero, a transfer encoding other than `chunked` in lower case, a chunk size with an extension or a space, a body on `GET` or `HEAD`, or trailers.

### Rules

- A rule allows a method on an exact host and path. A `*` path segment stands for exactly one segment; nothing else is a wildcard. The query is exact, empty, or any query that passes the checks above, as the rule says.
- A rule names the request headers forwarded upstream. Every other header is dropped.

### Forwarding

- The outbound request is built from the checked parts alone: the rule's host, the exact path and query matched, and the rule's headers. Nothing else of the inbound request is copied, and no header the agent names in `Connection` is ever forwarded.
- The upstream is the rule's host on port 443, with the certificate verified against the system roots. There is no way to turn verification off, and no outbound proxy from the environment.
- Every connection's address is checked as it is made, after resolution: loopback, private, carrier-grade NAT, link-local and metadata, documentation, benchmarking, multicast and reserved ranges, NAT64, 6to4 and its relay, IETF protocol assignments including Teredo, SRv6, site-local, unique local, IPv4-compatible, IPv4-translated and zoned IPv6 addresses are refused, IPv4-mapped addresses once unmapped.
- One upstream client per host: no connection is shared between destinations.
- Redirects are never followed. The agent sees them, and its next request is checked like any other.
- Bodies pass untouched, never decompressed. A body over 64 MiB is refused with `413`, never truncated.

### Responses

- Streamed as they arrive, flushed on every read, so Claude's server-sent events and keep-alives pass without delay. The upstream may take up to 10 minutes to start answering.
- A response cut off upstream aborts the connection to the agent, so a truncated body never ends cleanly. A `101`, or any status under 200 that ends the exchange, is answered with `502`, and so are response headers over 64 KiB.
- Hop-by-hop headers, headers named in `Connection`, `Set-Cookie` and `Alt-Svc` never reach the agent. Trailers are never copied.

### Limits and logs

- A request head is read within 30 seconds and bounded to 64 KiB. Idle connections close after 2 minutes. At most 256 connections from the agent at once.
- One JSON line per decision the proxy makes, including refused handshakes, with a stable reason code. A request head refused before it is parsed is logged with its reason, and none of its bytes. A line never holds a header value or a body, and never the placeholder or a secret: a method, host or target holding one is withheld. Every field is bounded, and control characters, C1 included, are escaped.
- A refusal answers with a fixed body naming its reason code, echoing nothing from the request.

### Credentials

- Every credential-bearing header the agent sends, `Authorization`, `X-Api-Key`, `Cookie`, `Proxy-Authorization`, `Private-Token`, `X-Goog-Api-Key`, `X-Goog-User-Project` and others, must be absent, or, in `Authorization` and `X-Api-Key`, exactly the placeholder as Claude Code and the GitHub CLI send it. It is then dropped. Anything else refuses the request: a credential of the agent's own never reaches a service.
- The placeholder anywhere else, or one of the user's real secrets, in a header or in the request target, raw or with its query decoded, refuses the request. Bodies are not searched: the agent never holds a real secret, and the placeholder in a body reaches no credential.
- The rule's credential is added last, to the request being sent, by whole value in one header: never into a body, a query or a path, and never from anything the agent sent.
- Google access tokens for Vertex are minted by the proxy from a user login or a service account key, with Google's token endpoint only, by a token source built once and independent of any request, which refreshes the token as it expires.
- The run's CA is constrained to the run's hosts.

### Claude's server-side tools

- A request to Claude's Messages API is read whole, at most 64 MiB, before it is forwarded as the same bytes. It must be valid UTF-8 and one JSON object with no key repeated at any depth, in any letter case, so the proxy and the API cannot read it differently.
- A tool that makes Anthropic's servers fetch, run or connect to anything, `web_fetch`, code execution or an MCP toolset, and any `mcp_servers`, refuses the request.
- `web_search` stays allowed, since Claude Code's WebSearch needs it and it only sends queries to Anthropic's search provider: `web_search_20250305`, or a later version whose `allowed_callers` is exactly `["direct"]`. Later versions otherwise let code execution call the search, which runs code on Anthropic's servers.
- An image or a document whose `source` is of type `url`, anywhere in the body, in any turn or tool result, refuses the request: Anthropic's servers would fetch that URL, carrying whatever it holds to its host.

### Tests

[Proxy tests](proxy-tests.md) lists every test, with its ID, its source and the outcome it requires:

- Unit tests for every check, rule, credential case, the Messages API inspection and both Google flows, against real TLS upstreams.
- Wire-level tests on real sockets: request smuggling, framing, pipelining, hostile upstreams, TLS server names, addresses, limits and the audit log.
- The run's real rules, driven through the proxy: what the user's credentials reach, and everything they never reach.
- Two fuzz tests: `FuzzCheckRequest`, checking that whatever is accepted is canonical, and `FuzzParDifferential`, checking that whatever the proxy accepts an independent strict RFC 9112 parser reads the same way.
- End-to-end tests of the real images against the real services, with Docker and rootless Podman, including a hostile plugin that tries every way out from inside the agent container.

## Not built yet

- Redaction of a credential an upstream echoes back.

## Before 1.0

The proxy holds the user's credentials, so Sealroom is not released as 1.0 before all of these are done:

- **Adversarial red-teaming by AI**: several independent sessions, each with its own angle (parsing and smuggling; TLS, server names and DNS; addresses and upstream behavior; credentials and placeholders; responses, logs and failing open), each told to break the complete proxy and the integrated run, and each finding counted only when a failing test proves it. Every proven finding is fixed, and its test kept. The sessions may share blind spots with whoever wrote the code, so this complements a human review rather than replacing it.
- **Fuzzing** of the request checks, for longer than CI's seed runs. Hours, not the minutes run so far.
- **Differential testing** against real servers: `FuzzParDifferential` compares the proxy with an independent strict parser written for the tests; the same comparison against the servers behind the allowed hosts, as HTTP Garden does, is not done.
- **A regression table of bypasses**: every trick from the advisories cited below, and from new ones, kept as a test. [Proxy tests](proxy-tests.md) is that table; it grows with every new advisory.
- **An independent human review**, if one can be found, by Red Hat Product Security or another reviewer. If none can, the README and `SECURITY.md` say plainly that the proxy has not had one.

## What it will never do

WebSocket, HTTP/2 toward the agent, `CONNECT`, plain HTTP, following redirects, GitHub's GraphQL endpoint, and any setting that weakens a check: no warning mode, no allow-all, no verification switch.

## Sources

- Envoy: CVE-2021-29492 (encoded slashes past RBAC), CVE-2026-73551 and CVE-2026-73553 (path parameters), CVE-2026-26308 and CVE-2021-32777 (duplicate headers), CVE-2026-73548 (poisoned upstream connections), CVE-2024-27919 (HTTP/2 CONTINUATION flood), and its [edge best practices](https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge).
- Traefik: CVE-2026-88009 (opaque request targets), CVE-2026-40912 (path desynchronization), CVE-2024-45410 and CVE-2026-29054 (Connection header abuse), CVE-2026-48491 and CVE-2026-32305 (SNI and Host mismatches).
- agentgateway: [issue 1023](https://github.com/agentgateway/agentgateway/issues/1023), paths matched without normalization.
- Smokescreen: CVE-2022-24825 and CVE-2022-29188 (trailing dots, case, brackets).
- Squid: CVE-2026-61642 (request smuggling), CVE-2025-62168 (credentials in error pages).
- Go: CVE-2021-33197 (ReverseProxy and Connection), CVE-2023-45289, CVE-2024-45336 and CVE-2025-4673 (credentials on redirects), CVE-2024-24790 (IPv4-mapped addresses), and [preventing SSRF in Go](https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang).
- iron-proxy v0.52.0, which Sealroom used before: its dial-time address check, its dot-segment refusal, and the weaknesses in [proxies considered](proxy-alternatives.md).
- Agent sandboxes: Anthropic's sandbox-runtime (CVE-2025-66479, an empty list meaning allow-all), Gondolin, nono, Docker Sandboxes, Vercel's firewall (SNI and Host), and [exfiltration through the Anthropic API with an attacker's key](https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/).
