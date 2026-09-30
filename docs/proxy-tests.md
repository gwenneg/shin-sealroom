# Proxy tests

Sealroom's proxy is the only way out of a run, and the only holder of the user's credentials. These tests treat every byte the agent sends, and every byte an upstream answers, as hostile: a malicious plugin, or a prompt injection steering Claude, controls the agent container entirely. They are the regression table [the proxy](proxy.md#before-10) requires before 1.0, drawn from published proxy CVEs, request-smuggling research and the exfiltration attacks seen against coding agents.

Every case has an ID, which starts its subtest name. Each one states the attack, its source, and the outcome the proxy must reach: refused with a reason code, or forwarded with exactly what the upstream must receive. A case marked **limit** pins a channel the proxy cannot close, and says why.

## Running them

- `go test -race ./internal/egress ./internal/proxy` runs every unit and wire-level test. `TestNetSlowClients` waits out the real 30-second limits; `-short` skips it.
- `go test -run=^$ -fuzz=FuzzParDifferential ./internal/egress` and `-fuzz=FuzzCheckRequest` run the fuzzers.
- `SEALROOM_E2E=1 go test -v ./internal/e2e/` runs the end-to-end tests against the real images and services, with Docker, or with Podman when `CONTAINER_RUNTIME=podman`. CI runs both.
- `images/proxy/smoke-test.sh IMAGE` checks a built proxy image.

## Contents

- [Core tests](#core-tests)
- [Parsing, framing and smuggling](#parsing-framing-and-smuggling) (PAR-)
- [Network, TLS and upstreams](#network-tls-and-upstreams) (NET-)
- [Credentials and exfiltration](#credentials-and-exfiltration) (CRE-)
- [A hostile plugin, end to end](#a-hostile-plugin-end-to-end) (E2E-)

## Core tests

The tests written with the proxy, one per mechanism, each with its refusals and its allowed forms.

| Test | What it checks |
|---|---|
| `TestCheckRequestRefuses`, `TestCheckRequestAccepts` | Every form, path, query, host and header check, both ways. |
| `TestMatch`, `TestValidateRefuses` | Rule matching, first match wins, and the configurations `Validate` refuses. |
| `TestDenied` | The addresses the proxy never connects to, embedded and translated forms included. |
| `TestDNS` | Answers for allowed names only, and nothing forwarded. |
| `TestCerts` | Certificates minted only for exact allowed names. |
| `TestForward`, `TestRedirectNotFollowed`, `TestRefusals`, `TestStreams` | The request rebuilt from scratch, redirects returned rather than followed, fixed refusal bodies, and streaming. |
| `TestServe` | The whole proxy on real sockets: DNS, TLS and HTTP together. |
| `TestCredentialRefusals`, `TestCredentialSchemes`, `TestPlaceholderDroppedWithoutCredential`, `TestNewRefusesMissingSecrets` | The placeholder, the agent's own credentials, and how the user's are added. |
| `TestMessages` | The Messages API inspection: server tools, MCP servers, URL sources, repeated keys, invalid UTF-8. |
| `TestGoogleTokens` | Google tokens minted from a service account and a user login, from Google's endpoint only. |
| `FuzzCheckRequest` | Whatever Go's parser and the checks accept is canonical. |
| `TestConfigRules`, `TestConfigDeclared`, `TestValidRepo`, `TestValidVertex`, `TestEnvFile`, `TestEnvFileVertex` (`internal/proxy`) | The rules generated for a run, what a plugin may declare, and the proxy's environment file. |
| `TestNewCA`, `TestCANameConstraints` (`internal/proxy`) | The run's CA, and that it cannot sign for a name outside the run's hosts. |
| `TestSession`, `TestProxyRules`, `TestProxyRulesVertex` (`internal/e2e`) | A whole run with the real images, and the real rules against the real services. |

## Parsing, framing and smuggling
These tests attack the proxy as a malicious plugin would: raw bytes on the agent's TLS connection. The harness, `internal/egress/parsing_harness_test.go`, runs the real proxy with `Serve` on real sockets, forwards to a raw TLS upstream that records byte for byte what it receives, and after each case sends one more request, a sentinel no rule allows, so that any request the proxy read from the case's bytes but the case did not expect shows as an extra answer. Each case states the answers the agent must read, the exact requests the upstream must receive, and that every answer of the proxy's own is one audit line.

Test names are as `go test -run` prints them, with underscores for spaces. The proxy reads the agent's raw stream itself, in `wireConn`, before Go's HTTP parser: anything Go's parser would normalize, a line ending, a folded line, a repeated or conflicting framing header, a chunk outside RFC 9112's grammar, a trailer, is refused there, with a reason code and an audit line. Go's server still refuses a few requests itself, with a 400 or a 417 and no audit line, for what `wireConn` leaves to the proxy's checks and Go rejects first: control bytes or a malformed escape in the target, a malformed `Host` value, and an expectation other than `100-continue`. None of them reaches the upstream.

Sources cited often:

- RFC 9112, HTTP/1.1: https://www.rfc-editor.org/rfc/rfc9112
- RFC 9110, HTTP semantics: https://www.rfc-editor.org/rfc/rfc9110
- James Kettle, HTTP Desync Attacks (2019): https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- James Kettle, Browser-Powered Desync Attacks (2022): https://portswigger.net/research/browser-powered-desync-attacks
- James Kettle, HTTP/1.1 Must Die (2025): https://portswigger.net/research/http1-must-die
- Tom Stacey and Tobia Righi, CRLF-Powered Desync Attacks (2026): https://portswigger.net/research/crlf-powered-desync-attacks
- Jeppe Bonde Weikop, Funky Chunks (2025): https://w4ke.info/2025/06/18/funky-chunks.html and https://w4ke.info/2025/10/29/funky-chunks-2.html
- HTTP Garden, differential fuzzing of HTTP parsers: https://github.com/narfindustries/http-garden
- Orange Tsai, Breaking Parser Logic (2018): https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- Orange Tsai, Confusion Attacks (2024): https://blog.orange.tw/posts/2024-08-confusion-attacks-en/
- Bishop Fox, h2c smuggling: https://bishopfox.com/blog/h2c-smuggling-request
- OWASP, path traversal encodings: https://owasp.org/www-community/attacks/Path_Traversal
- The CVEs named in the sources of [the proxy](proxy.md).

### Request line

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-001 | `TestParRequestLine/baseline`, `TestParRequestLine/HEAD` | None: the canonical request, to pin what the upstream receives. | [The proxy](proxy.md), forwarding | Allowed; the upstream receives exactly `GET / HTTP/1.1`, `Host: example.com`, `User-Agent: Go-http-client/1.1`, built by the proxy. |
| PAR-002 | `TestParRequestLine/HTTP/1.0`, `TestParRequestLine/HTTP/1.2` | Another HTTP/1 version, read with other framing rules by some servers. | RFC 9112 §2.3 | Refused, `request-form`. |
| PAR-003 | `TestParRequestLine/HTTP/2.0_in_a_request_line`, `TestParRequestLine/HTTP/0.9_version`, `TestParRequestLine/HTTP/0.9_simple_request` | HTTP/2 or HTTP/0.9 in an HTTP/1 request line, or a request with no version and no headers. | RFC 9112 §2.3; HTTP Garden | Refused, `request-form`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-004 | `TestParRequestLine/HTTP/2_preface` | The HTTP/2 connection preface on an HTTP/1.1 connection, to switch protocol without asking. | RFC 9113 §3.4; Bishop Fox h2c smuggling | Refused, `request-form`. |
| PAR-005 | `TestParRequestLine/lowercase_version`, `…/version_with_a_leading_zero`, `…/version_with_two_minor_digits`, `…/space_after_the_version`, `…/two_spaces_after_the_method`, `…/tab_as_a_separator`, `…/extra_field_in_the_request_line` | A request line one lenient parser splits differently from another. | RFC 9112 §3; HTTP Garden | Refused, `request-form`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-006 | `TestParRequestLine/lowercase_method`, `…/method_TRACE`, `…/unknown_method`, `…/method_with_a_byte_outside_token` | A method that a case-insensitive server would read as an allowed one, or one no rule names. | RFC 9110 §9.1 (methods are case-sensitive) | A lowercase method or a byte outside token is refused, `request-form`, refused by the strict reader before Go's parser reads it, logged; `TRACE` and an unknown method are refused, `no-rule`. |
| PAR-007 | `TestParRequestLine/absolute_form_of_the_same_host`, `…/absolute_form_in_http`, `…/absolute_form_of_another_host`, `…/absolute_form_of_a_host_only_another_rule_allows`, `…/opaque_form` | An absolute URI whose authority a server prefers over `Host`, or an opaque target. | RFC 9112 §3.2.2; Traefik CVE-2026-88009; Kettle 2019 | Refused, `request-form`. |
| PAR-008 | `TestParRequestLine/asterisk_form_with_GET` | The asterisk form with a method other than OPTIONS. | RFC 9112 §3.2.4 | Refused, `request-form`. |
| PAR-009 | `TestParRequestLine/asterisk_form_with_OPTIONS` | `OPTIONS * HTTP/1.1`. | RFC 9112 §3.2.4; Go's `Server.DisableGeneralOptionsHandler`, https://pkg.go.dev/net/http#Server.DisableGeneralOptionsHandler | Refused, `request-form`. Go's general `OPTIONS *` handler is off, so the request reaches the proxy's checks, which refuse anything not in origin form. Nothing reaches the upstream. |
| PAR-010 | `TestParRequestLine/CONNECT_in_authority_form`, `…/CONNECT_in_origin_form`, `…/authority_form_with_GET` | A tunnel, or the authority form with another method. | RFC 9112 §3.2.3 | Refused, `request-form`. |
| PAR-011 | `TestParRequestLine/query_without_a_path`, `…/empty_target`, `…/NUL_in_the_target`, `…/tab_in_the_target`, `…/DEL_in_the_target` | A target that is empty, not rooted, or holds a control byte. | RFC 9112 §3.2 | An empty target is refused, `request-form`, by the strict reader. A query without a path, or a NUL, tab or DEL in the target, is refused by Go's server with a 400, unlogged: the strict reader leaves the target's bytes to the proxy's checks, and Go refuses these first. |
| PAR-012 | `TestParRequestLine/bare_CR_ending_the_request_line` | A bare CR as a line end, read as one by some parsers only. | RFC 9112 §2.2 | Refused, `request-form`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-013 | `TestParRequestLine/empty_line_before_the_request_line` | An empty line before the request, which some servers skip and others read as a request. | RFC 9112 §2.2 | Refused, `request-form`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-014 | `TestParRequestLine/bare_LF_line_ends`, `…/bare_LF_ending_the_request_line`, `…/bare_LF_ending_the_header_section` | Lines ended by a bare LF, the leniency behind TERM.EXT and other line-end desyncs. | RFC 9112 §2.2 (a recipient MAY accept LF); Funky Chunks; Kettle 2025 | Refused, `request-form`, refused by the strict reader before Go's parser reads it, logged: every line must end with CRLF. |
| PAR-015 | `TestParRequestLine/request_line_over_the_header_limit` | A request line of 70 KiB. | [The proxy](proxy.md), limits | Refused, `too-large`, 431, refused by the strict reader before Go's parser reads it, logged. |

### Path

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-020 | `TestParPath/exact_path`, `…/one-segment_wildcard`, `…/one-segment_wildcard_with_every_allowed_byte`, `…/three_dots_are_a_name,_not_a_dot_segment`, `…/trailing_wildcard,_several_segments`, `…/path_of_2048_bytes` | None: canonical paths, including every byte the spec allows. | [The proxy](proxy.md), refusing before any rule | Allowed; the upstream receives the same path, byte for byte. `...` is a name, not a dot segment, for every server the rules name. |
| PAR-021 | `TestParPath/path_of_2049_bytes` | A path longer than the limit. | [The proxy](proxy.md) | Refused, `path`. |
| PAR-022 | `TestParPath/empty_segment`, `…/leading_double_slash`, `…/network-path_reference`, `…/trailing_slash`, `…/trailing_slash_on_a_wildcard` | Empty segments that a server merges, or reads as an authority. | agentgateway issue 1023, https://github.com/agentgateway/agentgateway/issues/1023; RFC 3986 §4.2; nginx `merge_slashes` | Refused, `path`. |
| PAR-023 | `TestParPath/dot_segment`, `…/dot-dot_segment`, `…/trailing_dot_segment`, `…/trailing_dot-dot_segment`, `…/dot-dot_in_a_wildcard`, `…/dot-dot_under_a_trailing_wildcard`, `…/root_dot`, `…/root_dot-dot` | Dot segments a server removes after the proxy matched the path. | RFC 3986 §5.2.4; Spring CVE-2024-38819, https://spring.io/security/cve-2024-38819; iron-proxy's dot-segment refusal | Refused, `path`. |
| PAR-024 | `TestParPath/encoded_dot-dot`, `…/encoded_dot-dot_in_capitals`, `…/half-encoded_dot-dot`, `…/encoded_dot`, `…/encoded_slash`, `…/encoded_slash_in_capitals`, `…/encoded_backslash` | Percent-encoded dots, slashes and backslashes a server decodes before routing. | Envoy CVE-2021-29492; Orange Tsai 2018 | Refused, `path`. |
| PAR-025 | `TestParPath/double-encoded_dot-dot`, `…/double-encoded_slash` | Double encoding, decoded once by each of two layers. | OWASP path traversal | Refused, `path`. |
| PAR-026 | `TestParPath/overlong_UTF-8_dot,_encoded`, `…/overlong_UTF-8_slash,_encoded`, `…/raw_overlong_UTF-8_slash`, `…/IIS_unicode_escape` | Overlong UTF-8 or `%u` escapes a lenient decoder reads as `.` or `/`. | OWASP path traversal | Refused, `path`; the `%u` form is refused by Go's server with a 400, unlogged. |
| PAR-027 | `TestParPath/encoded_unreserved_letters`, `…/encoded_NUL`, `…/encoded_space`, `…/encoded_question_mark`, `…/encoded_number_sign`, `…/lone_percent`, `…/invalid_escape` | Any other escape: an encoded `?` that truncates a path after decoding, a NUL, or an escape of a plain letter. | Apache CVE-2024-38474 (Orange Tsai 2024) | Refused, `path`; a lone `%` or a malformed escape is refused by Go's server with a 400, unlogged. |
| PAR-028 | `TestParPath/matrix_parameter`, `…/empty_matrix_parameter`, `…/Tomcat_dot-dot-semicolon`, `…/semicolon_in_a_wildcard`, `…/jsessionid`, `…/Envoy_dot-dot_with_a_parameter` | Path parameters that a server strips, before or after removing dot segments. | Envoy CVE-2026-73551 and CVE-2026-73553; Orange Tsai 2018 (`..;/` on Tomcat) | Refused, `path`. |
| PAR-029 | `TestParPath/backslash`, `…/backslash_dot-dot` | A backslash a server reads as a slash. | Orange Tsai 2018 | Refused, `path`. |
| PAR-030 | `TestParPath/raw_UTF-8`, `…/fullwidth_slash`, `…/raw_Latin-1_byte` | Raw non-ASCII bytes, among them a fullwidth slash that Unicode normalization turns into `/`. | Orange Tsai 2018 | Refused, `path`. |
| PAR-031 | `TestParPath/plus`, `…/comma`, `…/equals`, `…/asterisk`, `…/exclamation_mark`, `…/dollar`, `…/ampersand`, `…/apostrophe`, `…/parentheses`, `…/double_quote`, `…/angle_brackets`, `…/braces`, `…/pipe`, `…/caret`, `…/backquote`, `…/square_brackets` | Every sub-delimiter and other byte outside the spec's set, each read with a meaning by some framework. | RFC 3986 §3.3 | Refused, `path`. |
| PAR-032 | `TestParPath/other_letter_case`, `…/trailing_dot_in_a_name`, `…/trailing_tilde_in_a_name`, `…/two_segments_for_a_one-segment_wildcard`, `…/no_segment_for_a_trailing_wildcard`, `…/at_sign_first` | Near misses that a case-insensitive or trailing-dot-stripping server would route to an allowed path. | Smokescreen CVE-2022-24825 (case and trailing dots) | Refused, `no-rule`. |
| PAR-033 | `TestParPath/fragment` | A fragment in the request target, which some servers cut and others forward. | RFC 9112 §3.2 | Refused, `request-form`. |

### Query

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-040 | `TestParQuery/the_exact_query_of_a_rule`, `…/the_exact_query,_encoded`, `…/the_exact_query_in_capitals`, `…/the_exact_query_and_another_pair`, `…/the_exact_query_twice`, `…/the_exact_query_with_another_value_after`, `…/the_exact_name_in_capitals`, `…/no_query_where_a_rule_wants_one` | A query that a server decodes or merges into the one a rule names, or a repeated parameter whose last value a server takes. | OWASP HTTP parameter pollution (WSTG-INPV-04) | Only the exact bytes are allowed; the others are refused, `no-rule`. |
| PAR-041 | `TestParQuery/one_pair`, `…/empty_value`, `…/several_pairs`, `…/unreserved_bytes`, `…/encoded_slash,_forwarded_encoded`, `…/encoded_separators,_forwarded_encoded`, `…/query_of_2048_bytes`, `…/escaped_UTF-8` | None: strict queries on a rule that accepts any. | [The proxy](proxy.md) | Allowed; the upstream receives the same query, byte for byte, escapes undecoded. Escapes of bytes above 0x7f are accepted, for search terms in UTF-8. |
| PAR-042 | `TestParQuery/query_of_2049_bytes`, `…/empty_query`, `…/name_without_value`, `…/empty_name`, `…/trailing_ampersand`, `…/empty_pair`, `…/two_equals_signs`, `…/semicolon_separator` | A query that parsers split into different pairs. | [The proxy](proxy.md); Python CVE-2021-23336 (`;` as a separator) | Refused, `query`. |
| PAR-043 | `TestParQuery/plus`, `…/slash`, `…/colon`, `…/at_sign`, `…/question_mark`, `…/comma`, `…/asterisk`, `…/raw_UTF-8` | A byte outside the strict set, `+` read as a space by some decoders. | RFC 3986 §3.4 | Refused, `query`. |
| PAR-044 | `TestParQuery/invalid_escape`, `…/truncated_escape`, `…/lone_percent`, `…/encoded_NUL`, `…/encoded_CRLF`, `…/encoded_tab` | Malformed escapes, and escapes of control bytes that a server decodes into a header or a log. | CRLF-Powered Desync 2026 (`%0d%0a` decoded into an upstream request) | Refused, `query`. |
| PAR-045 | `TestParQuery/encoded_DEL` | `%7F`, the DEL control byte, escaped. | [The proxy](proxy.md): "well-formed escapes of printable bytes" | Refused, `query`: `checkQuery` refuses escapes of control bytes and of DEL. Escapes of bytes over 0x7F stay allowed, for UTF-8 search terms. |
| PAR-046 | `TestParQuery/fragment_after_the_query` | A fragment after the query. | RFC 9112 §3.2 | Refused, `request-form`. |

### Host and authority

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-050 | `TestParHost/the_server_name`, `…/port_443`, `…/no_space`, `…/spaces_around`, `…/lowercase_header_name` | None: the accepted forms of `Host`. | RFC 9110 §7.2 | Allowed; the upstream receives `Host` as the rule's host, without the port. |
| PAR-051 | `TestParHost/port_80`, `…/port_8443`, `…/empty_port`, `…/port_443_with_a_leading_zero`, `…/port_443_twice`, `…/port_alone` | Port variants that a server ignores or reads as another origin. | Smokescreen CVE-2022-29188 | Refused, `host`. |
| PAR-052 | `TestParHost/capitals`, `…/one_capital`, `…/trailing_dot`, `…/trailing_dot_and_port` | The same name in another case or with a trailing dot. | Smokescreen CVE-2022-24825 | Refused, `host`. |
| PAR-053 | `TestParHost/userinfo`, `…/userinfo_naming_another_host` | Userinfo in `Host`, which URL parsers split at different `@`. | RFC 9110 §4.2.4 | Refused by Go's server with a 400, unlogged: it refuses a malformed `Host` before the proxy sees the request. |
| PAR-054 | `TestParHost/IPv6_loopback`, `…/IPv4_loopback`, `…/the_proxy's_address`, `…/metadata_address` | An address instead of the name. | [The proxy](proxy.md) | Refused, `host`. |
| PAR-055 | `TestParHost/two_hosts_with_a_comma`, `…/two_hosts_with_a_space` | A list of hosts, the first or last taken by different servers. | Kettle 2019 | Refused, `host`; with a space, refused by Go's server with a 400, unlogged. |
| PAR-056 | `TestParHost/empty`, `…/missing`, `…/twice_the_same`, `…/twice,_another_host_second`, `…/twice_in_two_cases` | No `Host`, or two. | RFC 9112 §3.2; Kettle 2019 | Refused, `host`: empty by the proxy's checks; missing or twice refused by the strict reader before Go's parser reads it, logged. |
| PAR-057 | `TestParHost/encoded_dot`, `…/punycode`, `…/Cyrillic_homograph` | An encoded or IDN name that displays or decodes as the allowed one. | IDN homograph attacks; Unicode TR 39 | Refused, `host`; raw non-ASCII is refused, `header`, by the strict reader before Go's parser reads it, logged. |
| PAR-058 | `TestParHost/another_allowed_host`, `…/a_subdomain`, `…/a_parent` | Another name, allowed or near. | [The proxy](proxy.md) | Refused, `host`. |
| PAR-059 | `TestParHost/continued_on_a_folded_line`, `…/space_before_the_colon` | A `Host` folded onto a second line, or with whitespace before its colon. | RFC 9112 §5.1 and §5.2; Go CVE-2019-16276 | Refused, `header`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-060 | `TestParHost/path_of_another_host's_rule`, `TestParHost/another_server_name,_this_Host`, `TestParHost/the_second_host_on_its_own_name` | A TLS server name for one allowed host and a `Host` for another, to reach a path only the other's rule allows. | Traefik CVE-2026-48491 and CVE-2026-32305; Vercel's firewall | Refused, `host`; on its own name, allowed, and the upstream connection's TLS server name is that host. |
| PAR-061 | `TestParHost/X-Forwarded-Host_is_never_forwarded`, `…/Forwarded_is_never_forwarded`, `…/X-Original-URL_is_never_forwarded`, `…/X-Rewrite-URL_is_never_forwarded`, `…/X-HTTP-Method-Override_is_never_forwarded`, `…/x-middleware-subrequest_is_never_forwarded` | Headers that make a framework override the host, the path or the method, or skip its middleware. | Next.js CVE-2025-29927; PortSwigger Web Security Academy, access control, https://portswigger.net/web-security/access-control | Allowed; none of them reaches the upstream. |

### Headers

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-070 | `TestParHeaders/a_listed_header_is_forwarded`, `…/listed_headers_are_forwarded,_in_Go's_order`, `…/an_unlisted_header_is_dropped`, `…/a_name_in_capitals_is_the_same_header`, `…/a_name_in_lowercase_is_the_same_header`, `…/spaces_around_a_value_are_not_part_of_it`, `…/tab_inside_a_value`, `…/an_empty_value_is_not_forwarded`, `…/a_value_of_8_KiB`, `…/a_hundred_headers` | None: what reaches the upstream of the agent's headers. | [The proxy](proxy.md), rules | Allowed; the upstream receives exactly the rule's headers, in canonical case, with the value the checks saw. |
| PAR-071 | `TestParHeaders/a_thousand_headers` | Many small headers, to exhaust a parser. | Go 1.27's `Server.MaxHeaderValueCount`, 500 by default, https://pkg.go.dev/net/http#Server | Refused, `header`, refused by the strict reader before Go's parser reads it, logged: more than 128 header lines. |
| PAR-072 | `TestParHeaders/twice`, `…/twice_in_two_cases`, `…/an_unlisted_header_twice`, `…/Accept_twice,_as_a_list_would_be_merged`, `…/credential_header_twice_in_two_cases` | The same header twice, in the same or another case, read first-wins by one server and last-wins or merged by another. | Envoy CVE-2026-26308 and CVE-2021-32777 | Refused, `header`. |
| PAR-073 | `TestParHeaders/underscore_in_a_name`, `…/underscore_in_a_credential_name` | An underscore, which CGI-style servers turn into a dash. | nginx `underscores_in_headers`; CGI's `HTTP_` variables | Refused, `header`. |
| PAR-074 | `TestParHeaders/name_with_!` … `TestParHeaders/name_with_~` (13 cases) | Every token byte Go's server takes in a name and the spec does not. | RFC 9110 §5.6.2 | Refused, `header`. |
| PAR-075 | `TestParHeaders/UTF-8_in_a_value`, `…/Latin-1_byte_in_a_value`, `…/DEL_in_a_value`, `…/control_byte_in_a_value`, `…/NUL_in_a_value`, `…/bare_CR_in_a_value`, `…/bare_CR_then_a_byte,_SPILL.TERM` | A value byte outside visible ASCII, among them a bare CR that some parsers end a line on. | RFC 9110 §5.5; Funky Chunks (SPILL.TERM) | Refused, `header`, refused by the strict reader before Go's parser reads it, logged; a bare CR is refused, `request-form`, as a line ending that is not CRLF. |
| PAR-076 | `TestParHeaders/DEL_in_a_name`, `…/UTF-8_in_a_name`, `…/empty_name`, `…/no_colon` | A malformed field line. | Go issue 65244, https://github.com/golang/go/issues/65244 (empty names, found by HTTP Garden) | Refused, `header`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-077 | `TestParHeaders/space_before_the_colon`, `…/tab_before_the_colon`, `…/space_inside_a_name`, `…/whitespace_before_the_first_header` | Whitespace in or after a name, read as part of the name by some parsers and stripped by others. | Go CVE-2019-16276; RFC 9112 §5.1 | Refused, `header`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-078 | `TestParHeaders/folded_value`, `…/folded_value_with_a_tab`, `…/folded_empty_first_line`, `…/folded_credential,_as_the_placeholder` | Obsolete line folding, the classic way to hide a value from one parser. | RFC 9112 §5.2; Kettle 2019 | Refused, `header`, refused by the strict reader before Go's parser reads it, logged: no value is unfolded, and a folded `Authorization` never passes as the placeholder. |
| PAR-079 | `TestParHeaders/header_section_of_70_KiB`, `TestParHeaders/header_section_of_66_KiB` | A header section over the 64 KiB bound. | [The proxy](proxy.md), limits; Go's `initialReadLimitSize`, https://go.dev/src/net/http/server.go | Both refused, `too-large`, 431, refused by the strict reader before Go's parser reads it, logged: the head is bounded at 64 KiB exactly, whatever slack Go's server allows. |

### Connection, Upgrade and Expect

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-080 | `TestParConnection/keep-alive`, `…/Keep-Alive_in_capitals`, `…/close` | None: the values Claude Code, git and gh send. | [The proxy](proxy.md) | Allowed; after `close`, the connection reads no further request. |
| PAR-081 | `TestParConnection/naming_a_listed_header`, `…/close_and_a_header`, `…/keep-alive_and_close`, `…/twice`, `…/naming_Upgrade`, `…/naming_TE`, `…/naming_Host`, `…/naming_a_credential_header` | `Connection` naming headers, to have a hop strip one the next relies on. | Go CVE-2021-33197; Traefik CVE-2024-45410 | Refused, `header`. |
| PAR-082 | `TestParConnection/Keep-Alive_is_not_forwarded`, `…/Proxy-Connection_is_not_forwarded`, `…/TE_is_not_forwarded`, `…/HTTP2-Settings_alone_is_not_forwarded` | Hop-by-hop headers on their own. | RFC 9110 §7.6.1 | Allowed; none reaches the upstream. |
| PAR-083 | `TestParConnection/h2c_upgrade`, `…/h2c_upgrade_without_Connection`, `…/WebSocket_upgrade`, `…/upgrade_to_HTTP/2.0`, `…/empty_Upgrade_asks_for_nothing` | An upgrade that turns the connection into a tunnel no check reads. | Bishop Fox h2c smuggling; RFC 9110 §7.8 | Refused, `request-form`; an empty `Upgrade` asks for nothing and is allowed. |
| PAR-084 | `TestParConnection/Expect_100-continue`, `…/Expect_in_another_case`, `…/obfuscated_Expect`, `…/Expect_folded`, `…/Expect_on_GET`, `…/Expect_of_something_else`, `…/Expect_twice`, `…/empty_Expect,_as_git_sends` | `Expect`, plain or obfuscated, the basis of the 2025 Expect-based desyncs. | Kettle 2025; Akamai CVE-2025-32094; Go CVE-2024-24791 | Refused, `request-form`; folded, refused, `header`, refused by the strict reader before Go's parser reads it, logged; another expectation is answered `417` by Go's server, unlogged; twice is refused, `header`; empty is allowed. |
| PAR-085 | `TestParExpectNoInterim` | A refused `Expect: 100-continue` answered with an interim 100, inviting the agent to send a body the proxy would then read as a request. | Kettle 2025 | The agent reads one 403 and no `100 Continue`. |
| PAR-086 | `TestParConnection/Trailer_declared_without_a_body` | `Trailer` on a request without a body. | RFC 9110 §6.6.2 | Allowed; it declares nothing and is not forwarded. |

### Framing

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-090 | `TestParFraming/Content-Length`, `…/Content-Length_0`, `…/no_framing`, `…/chunked`, `…/chunked_in_several_chunks`, `…/chunk_size_with_leading_zeros`, `…/chunk_size_in_capitals`, `…/chunked_after_a_tab` | None: valid framings, among them forms RFC 9112 allows but some parsers misread. | RFC 9112 §6 and §7.1 | Allowed; the upstream receives the body with the proxy's own framing: `Content-Length` with its value in canonical form, or chunked. |
| PAR-091 | `TestParFraming/Content-Length_over_the_body_limit` | A body over 64 MiB. | [The proxy](proxy.md) | Refused, `too-large`, 413. |
| PAR-092 | `TestParFraming/Content-Length_with_a_plus_sign`, `…/negative_Content-Length`, `…/Content-Length_list`, `…/hexadecimal_Content-Length`, `…/Content-Length_with_an_exponent`, `…/Content-Length_overflowing_64_bits`, `…/empty_Content-Length`, `…/two_different_Content-Lengths` | A length that parsers read as different numbers. | Go issue 61679, https://github.com/golang/go/issues/61679 (empty length, found by HTTP Garden); RFC 9110 §8.6 | Refused, `body`, refused by the strict reader before Go's parser reads it, logged. |
| PAR-093 | `TestParFraming/the_same_Content-Length_twice`, `…/the_same_Content-Length_in_two_cases` | The same length twice, merged by Go's server into one. | [The proxy](proxy.md): "a header appears twice" is refused; RFC 9110 §8.6 | Refused, `body`, refused by the strict reader before Go's parser reads it, logged: framing headers repeated. |
| PAR-094 | `TestParFraming/Content-Length_and_chunked`, `…/chunked_and_Content-Length` | Both framings, the CL.TE and TE.CL desyncs. | Kettle 2019; RFC 9112 §6.1 and §6.3 | Refused, `body`, refused by the strict reader before Go's parser reads it, logged, and the connection closes. |
| PAR-095 | `TestParFraming/folded_Transfer-Encoding` | `Transfer-Encoding` folded onto a second line. | Kettle 2019 (TE obfuscation) | Refused, `header`, refused by the strict reader before Go's parser reads it, logged: a folded line. |
| PAR-096 | `TestParFraming/chunked_twice_in_one_header`, `…/chunked_in_two_headers`, `…/identity`, `…/gzip`, `…/gzip_then_chunked`, `…/chunked_then_gzip`, `…/chunked_with_a_parameter`, `…/a_near-chunked_coding`, `…/chunked_with_a_vertical_tab` | Transfer codings other than one `chunked`. | Go CVE-2022-1705; Kettle 2019 | Refused, `body`, refused by the strict reader before Go's parser reads it, logged: the only coding is one lowercase `chunked`. A vertical tab is refused, `header`, as a byte outside the printable range. |
| PAR-097 | `TestParFraming/Trailer_declared_on_a_chunked_body` | Trailers declared in the header. | [The proxy](proxy.md) | Refused, `header`. |
| PAR-098 | `TestParFraming/trailer_section_on_a_chunked_body`, `…/Transfer-Encoding_in_a_trailer`, `…/inspected_chunked_body_with_a_trailer_section` | A trailer section after the last chunk, undeclared, read as headers by servers that merge trailers. | [The proxy](proxy.md): trailers are refused; RFC 9112 §7.1.2 | Refused: the strict reader accepts only an empty trailer section and stops the body before its end, so the upstream never receives the whole body. Refused, `body`, whether the body is inspected or streamed. |
| PAR-099 | `TestParFraming/space_after_a_chunk_size`, `…/control_byte_in_a_chunk_extension,_EXT.TERM`, `…/chunk_extension`, `…/chunked_in_capitals`, `…/Content-Length_with_leading_zeros` | Chunk lines outside RFC 9112's grammar that Go's reader tolerates, and framing forms RFC 9112 allows but Go's parser normalizes: any chunk extension, `CHUNKED`, a length with leading zeros. | Funky Chunks; RFC 9112 §7.1 and §7.1.1 | Refused, `body`, by the strict reader: a head is refused before Go's parser reads it; a chunk line stops the body before its end reaches Go's parser, so the upstream never receives a complete request. Nothing is normalized and forwarded. |
| PAR-100 | `TestParFraming/bare_LF_after_a_chunk_size,_CVE-2025-22871`, `…/bare_LF_after_chunk_data`, `…/bare_CR_after_chunk_data`, `…/chunk_data_longer_than_its_size,_TERM.SPILL`, `…/chunk_data_shorter_than_its_size`, `…/bare_LF_in_a_chunk_extension,_TERM.EXT`, `…/quoted_CRLF_in_a_chunk_extension`, `…/hexadecimal_prefix_in_a_chunk_size`, `…/negative_chunk_size`, `…/chunk_size_overflowing_64_bits`, `…/empty_chunk_size`, `…/chunked_body_ended_by_an_empty_line,_go#64517` | Malformed chunks, each a known chunk-parsing differential. | Go CVE-2025-22871, https://pkg.go.dev/vuln/GO-2025-3563; Funky Chunks parts 1 and 2; Go issue 64517, https://github.com/golang/go/issues/64517; Go CVE-2023-39326 | Refused, `body`. The head was already forwarded, so the upstream receives it with a body that never reaches its end: it cannot act on it. |
| PAR-101 | `TestParFraming/inspected_chunked_body,_forwarded_with_its_length`, `…/inspected_chunked_body,_malformed` | A chunked body on a rule that reads it whole. | [The proxy](proxy.md), Claude's server-side tools | Allowed and forwarded with `Content-Length`; malformed, refused, `body`, before anything reaches the upstream. |
| PAR-102 | `TestParFraming/Content-Length_on_GET`, `…/Content-Length_0_on_GET`, `…/chunked_on_GET,_TE.0`, `…/Content-Length_on_HEAD`, `…/chunked_on_HEAD` | A body on GET or HEAD, which servers that ignore it read as the next request. | Kettle 2025 (0.CL, CL.0); TE.0 | Refused, `body`; `Content-Length: 0` is allowed. |
| PAR-103 | `TestParFraming/body_on_DELETE`, `…/PUT_without_a_body` | None: the framing of other methods. | RFC 9110 §9.3 | Allowed; forwarded with their length. |
| PAR-104 | `TestParParseRefusalsAudited/space_before_a_colon`, `…/two_Host_headers`, `…/unknown_coding`, `…/header_section_too_large` | Requests Go's server refuses before the proxy sees them. | [The proxy](proxy.md): one JSON line per decision, "including … parse-level refusals"; a refusal names its reason code | One audit line each, with its reason code: each is refused by the strict reader before Go's parser reads it, logged. |

### Pipelining

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-110 | `TestParPipelining/two_allowed`, `…/ten_allowed,_in_order` | Several requests in one write. | RFC 9112 §9.3.2 | Each answered in order; the upstream receives each, in order. |
| PAR-111 | `TestParPipelining/allowed,_then_a_dot-dot_path`, `…/allowed,_then_another_host`, `…/allowed,_then_the_path_of_another_host's_rule`, `…/allowed,_then_absolute_form`, `…/allowed,_then_the_agent's_own_credential`, `…/allowed_twice,_then_an_upgrade` | A hostile request behind allowed ones, hoping it rides on their decision. | Kettle 2019 | Each checked on its own: the hostile one is refused and never reaches the upstream. |
| PAR-112 | `TestParPipelining/allowed,_then_a_parse_error` | A malformed request behind an allowed one, with an allowed one after. | HTTP Garden | Refused, `header`, by the strict reader, and the connection closes: the third is never read. |
| PAR-113 | `TestParPipelining/refused,_then_allowed:_nothing_after_a_refusal_is_read`, `…/Connection_close,_then_allowed:_nothing_after_it_is_read` | Bytes after a refusal or after `Connection: close`. | Kettle 2022 (connection state) | The connection closes; nothing after is read. |
| PAR-114 | `TestParPipelining/a_request_in_a_body_is_a_body`, `…/a_request_in_a_chunk_is_a_body` | A request inside a correctly framed body. | Kettle 2019 | Forwarded as body bytes, never read as a request. |
| PAR-115 | `TestParPipelining/a_short_Content-Length_leaves_a_hostile_request,_checked_on_its_own`, `…/a_short_Content-Length_leaves_an_allowed_request,_checked_on_its_own`, `…/after_the_last_chunk,_a_hostile_request,_checked_on_its_own`, `…/unframed_bytes_after_a_GET_are_the_next_request,_CL.0` | Bytes past the framing, read as the next request. | Kettle 2019; Kettle 2025 (CL.0) | Each is a request of its own, checked on its own. |
| PAR-116 | `TestParPipelining/a_GET_with_a_body_hiding_a_request,_0.CL`, `…/a_chunked_GET_hiding_a_request,_TE.0`, `…/Expect_with_a_body_hiding_a_request`, `…/obfuscated_Expect_with_a_body_hiding_a_request`, `…/an_h2c_upgrade_followed_by_a_preface` | A request hidden in a body that a server would skip, or after an upgrade. | Kettle 2025; Bishop Fox h2c smuggling | Refused; the connection closes and the hidden request is never read. |
| PAR-117 | `TestParPipelining/HEAD,_then_GET` | A HEAD answer's framing confusing the next answer. | Kettle 2022 | Both answered, each with its own answer. |
| PAR-118 | `TestParPipelining/CL.TE,_the_bytes_after_the_last_chunk_read_as_a_request` | CL.TE: `Content-Length: 4` with `0\r\n\r\n` chunked, then a request. | Kettle 2019; RFC 9112 §6.1 | Refused, `body`, refused by the strict reader before Go's parser reads it, logged, and the connection closes: nothing reaches the upstream. |

### Responses

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-120 | `TestParResponses/Content-Length_and_chunked:_read_as_chunked,_framed_once` | An upstream answer with both framings. | RFC 9112 §6.3 | Read as chunked; the agent's answer has one framing. |
| PAR-121 | `TestParResponses/two_different_Content-Lengths`, `…/Content-Length_list`, `…/unknown_coding` | Answer framing that parsers read differently. | RFC 9112 §6.3 | Refused, `upstream`, 502. |
| PAR-122 | `TestParResponses/an_interim_100_Continue_is_not_passed_on`, `…/103_Early_Hints_are_not_passed_on` | Interim answers, among them hints naming another origin. | RFC 9110 §15.2 | The agent reads the final answer only. |
| PAR-123 | `TestParResponses/hop-by-hop_headers_are_dropped`, `…/Set-Cookie_and_Alt-Svc_are_dropped,_in_any_case`, `…/trailers_are_never_copied` | Hop-by-hop headers, headers named in `Connection`, cookies, `Alt-Svc`, trailers. | [The proxy](proxy.md), responses | None reaches the agent; other headers do. |
| PAR-124 | `TestParResponses/a_folded_header_is_not_passed_on_folded`, `…/a_bare_CR_in_a_header_is_refused` | An upstream header hiding another by folding or a bare CR. | RFC 9112 §5.2; CRLF-Powered Desync 2026 | Never passed on as a separate header; a bare CR is refused, `upstream`. |
| PAR-125 | `TestParResponses/an_answer_framed_by_closing_is_framed_again`, `…/bytes_past_Content-Length_are_dropped` | An answer framed by closing, and bytes after a framed answer. | RFC 9112 §6.3 | Framed again for the agent; extra bytes dropped. |
| PAR-126 | `TestParResponseQueuePoisoning/two_answers_to_one_request`, `…/a_body_on_an_answer_to_HEAD`, `…/a_body_on_a_204`, `…/a_body_on_a_304` | Response queue poisoning: extra bytes on the upstream connection read as the answer to the agent's next request. | Kettle 2022; Envoy CVE-2026-73548 | Over ten rounds, the next request always reads its own answer, never the extra one. |
| PAR-127 | `TestParResponseSwitchingProtocols` | An upstream answering 101 to a request that asked for no upgrade. | RFC 9110 §15.2.2 | The tunnel's bytes never reach the agent, and the next request is still checked. The 101 itself never reaches the agent either: any status under 200 that ends the exchange is refused, `upstream`, 502. |
| PAR-128 | `TestParResponseShortBody` | An upstream declaring a longer body than it sends. | RFC 9112 §8 | The agent reads a cut answer and a closed connection. |
| PAR-129 | `TestParResponseCutBody/malformed_chunk`, `…/connection_closed_mid-body`, `…/chunk_longer_than_announced` | An upstream body that breaks off in a chunked answer. | RFC 9112 §8 (incomplete messages) | The agent's connection is aborted, with no final chunk, so a broken stream never looks complete. |
| PAR-130 | `TestParHTTP2Upstream` | None: fidelity over HTTP/2 to the upstream. | [The proxy](proxy.md), forwarding | The upstream reads the same method, path, query, authority, headers and body the checks saw. |

### Fuzzing

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| PAR-140 | `FuzzParDifferential` | Any raw request: the strict reader, Go's parser and the proxy's checks against an independent strict RFC 9112 head parser (`parStrict`), comparing method, target, Host, every header value and framing. | HTTP Garden; [the proxy](proxy.md), before 1.0: differential testing | Whatever the proxy accepts, the strict parser accepts and reads the same way. The fuzz target feeds each input through `wireConn` first, as the server does, so its seeds for bare LF, folding, a repeated `Content-Length` and both framings are refused before Go's parser, as PAR-014, PAR-078, PAR-093 and PAR-094. |

## Network, TLS and upstreams
These tests cover the proxy's network edge: the addresses it may connect to, the DNS it answers, the TLS it speaks to the agent and to upstreams, what a hostile upstream can send back, the limits that bound a hostile agent, and the audit log. They live in `internal/egress/net_*_test.go`, and every helper they add starts with `net`.

Each entry names the Go test and subtest, the attack in one sentence, its source, and the behavior expected.

Run them with `go test -race ./internal/egress`. `TestNetSlowClients` waits out the real 30-second limits, in parallel, and is skipped with `-short`.

### Addresses and dialing

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| NET-001 | `TestNetDeniedAddresses`, the IPv4 subtests from `0.0.0.0` to `255.255.255.255` | Reach the proxy's own machine, a private network or a reserved range, at either end of each range. | [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/) | `denied` is true for each. |
| NET-002 | `TestNetDeniedAddresses/172.17.0.1`, `/10.88.0.1` | Reach the container runtime's bridge gateway, that is, the host. | Docker and Podman default networks | Denied. |
| NET-003 | `TestNetDeniedAddresses/169.254.169.254`, `/169.254.170.2`, `/169.254.169.123`, `/169.254.169.253`, `/169.254.0.23`, `/100.100.100.200`, `/192.0.0.192`, `/fd00:ec2::254`, `/fd00:ec2::23` | Reach a cloud metadata service: AWS (IPv4, IPv6, ECS), GCP, Azure, DigitalOcean, OpenStack, Tencent, Alibaba, Oracle. | [PayloadsAllTheThings, SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery), [AWS IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html) | Denied. |
| NET-004 | `TestNetDeniedAddresses`, the IPv6 subtests `::` to `100::1` | Reach the loopback, link-local, unique local, multicast, documentation or discard ranges over IPv6. | [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/) | Denied. |
| NET-005 | `TestNetDeniedAddresses/::ffff:127.0.0.1` and the other `::ffff:` subtests | Hide the loopback or the metadata address in an IPv4-mapped IPv6 address. | [CVE-2024-24790](https://nvd.nist.gov/vuln/detail/CVE-2024-24790) | Denied once unmapped. |
| NET-006 | `TestNetDeniedAddresses/64:ff9b::a9fe:a9fe`, `/64:ff9b::127.0.0.1`, `/64:ff9b::8.8.8.8`, `/64:ff9b:1::a9fe:a9fe`, `/64:ff9b:1:ffff::1` | Reach an internal IPv4 address through a NAT64 translator, by the well-known or the local-use prefix. | [CVE-2026-48782](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59), RFC 6052, RFC 8215 | Denied, whatever the embedded address. |
| NET-007 | `TestNetDeniedAddresses/2002:a9fe:a9fe::1`, `/2002:7f00:1::`, `/2001:0:4136:e378:8000:63bf:56fe:5601`, `/2001::1` | Embed the metadata address or the loopback in 6to4 or Teredo, including Teredo's obfuscated client address. | [CVE-2026-48782](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59), RFC 3056, RFC 4380 | Denied. |
| NET-008 | `TestNetDeniedAddresses/fe80::1%eth0`, `/fe80::1%1`, `/2606:4700:4700::1111%eth0`, `/::ffff:1.1.1.1%eth0`, `/the zero Addr` | Steer a connection to an interface with a zone, or slip an invalid address through. | [Preventing SSRF in Go](https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang) | Denied, even for a public address with a zone. |
| NET-009 | `TestNetDeniedGaps/::7f00:1`, `/::a9fe:a9fe` | Reach the loopback or the metadata address through the deprecated IPv4-compatible form `::a.b.c.d`. | [CVE-2026-48782](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59), RFC 4291 | Refused: `::/96` is denied. |
| NET-010 | `TestNetDeniedGaps/::ffff:0:a9fe:a9fe` | Embed the metadata address in an IPv4-translated (SIIT) address. | RFC 2765, [CVE-2026-48782](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59) | Refused: `::ffff:0:0:0/96` is denied. |
| NET-011 | `TestNetDeniedGaps/2001:2::1`, `/3fff::1` | Use the IPv6 benchmarking or the new documentation range, both of which the spec says are refused. | RFC 5180, RFC 9637, [IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/) | Refused: `2001::/23` and `3fff::/20` are denied. |
| NET-012 | `TestNetDeniedGaps/5f00::1`, `/fec0::1`, `/100:0:0:1::1`, `/192.88.99.1` | Use another range that is not globally reachable: SRv6 SIDs, deprecated site-local, the dummy prefix, the 6to4 relay anycast. | RFC 9602, RFC 3879, RFC 9780, RFC 7526 | Refused: each range is denied. |
| NET-013 | `TestNetAllowedPublic`, 35 subtests | Break real services with a deny list wider than its ranges. | Range boundaries from the IANA registries | The address just outside each range, and the addresses of GitHub, Anthropic, Google and Cloudflare, are allowed. |
| NET-014 | `TestNetControlDial/allowed …` and `/refused …` | Hand the dialer a denied address, a mapped or zoned one, or a public one on another port than 443. | [Preventing SSRF in Go](https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang) | A public address on 443 passes; every other is a `forbidden-address` refusal. |
| NET-015 | `TestNetControlDial/malformed …` | Hand the dialer a name, a decimal, octal or hex address, a short form, a missing or out-of-range port. | PayloadsAllTheThings, SSRF | An error: no form is guessed at. |
| NET-016 | `TestNetAddressEncodings`, 32 subtests | Write the loopback or the metadata address as decimal, octal, hex, short, mixed, full-width or circled digits, a trailing dot, percent-encoding, or a name such as `localhost`. | PayloadsAllTheThings, SSRF; [CVE-2021-29923](https://nvd.nist.gov/vuln/detail/CVE-2021-29923) | Go's parsers read none as a public address, and none is accepted as a rule's host. |
| NET-017 | `TestNetDialChecksResolvedAddress`, 7 subtests | Have the proxy's own client connect to the loopback by address, by `localhost`, or by a mapped form, on any port. | [Preventing SSRF in Go](https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang) | A `forbidden-address` refusal before connecting: the loopback listener never sees a connection. |
| NET-018 | `TestNetRebinding/loopback at once`, `/metadata at once`, `/mapped metadata at once` | Make a rule's host resolve to a private address. | DNS rebinding; iron-proxy's dial-time check | The connection is refused when it is made, the agent gets 403 `forbidden-address`, and the line is logged. |
| NET-019 | `TestNetRebinding/public, then private`, `/public, then loopback` | Answer with a public address first, then a private one for the next connection. | DNS rebinding, [Preventing SSRF in Go](https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang) | The first request is served, the second is refused at its own connection. |
| NET-020 | `TestNetUpstreamAddressIsTheRule` | Steer the upstream address or port through the request's `Host`. | Spec: no port ever comes from a request | The proxy always dials the rule's host on port 443. |

### DNS

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| NET-021 | `TestNetDNSAllowed/A` | Learn anything but the proxy's address for an allowed name. | Spec | One A answer, the proxy's address, TTL 60, authoritative, ID and RD echoed, no recursion offered. |
| NET-022 | `TestNetDNSAllowed/0x20 case kept in the question`, `/recursion not desired` | Break a resolver that randomizes case, or one that asks for no recursion. | [draft-vixie-dnsext-dns0x20](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00) | Answered, with the question's case kept. |
| NET-023 | `TestNetDNSAllowed/AAAA` to `/SPF`, 12 types | Carry data in through TXT, SVCB, HTTPS, MX or another type, or get an IPv6 answer. | DNS tunneling | NOERROR with no answer for every type but A. |
| NET-024 | `TestNetDNSOtherNames`, 18 named subtests | Resolve a subdomain, a parent, a look-alike, a suffix, `localhost`, a metadata name, a reverse name or an ACME name, or encode data in a label. | DNS exfiltration | NXDOMAIN, for A and TXT, with no answer. |
| NET-025 | `TestNetDNSOtherNames/NUL byte`, `/newline`, `/high bytes`, `/space`, `/63-byte label`, `/escaped quotes` | Put bytes no hostname holds in a label on the wire. | RFC 1035 | NXDOMAIN. |
| NET-026 | `TestNetDNSNotImplemented`, 8 subtests | Ask in the CHAOS, HESIOD or ANY class, or with an IQUERY, STATUS, NOTIFY or UPDATE opcode. | RFC 1035, RFC 2136 | NOTIMP with no answer. |
| NET-027 | `TestNetDNSMalformed`, 17 subtests | Send a packet that is empty, short, truncated, a response, or holds a pointer loop, a pointer past the end, a reserved label type, a dot inside a label, or a name over 255 bytes. | [golang/go#56246](https://github.com/golang/go/issues/56246), RFC 1035 | No answer, and no panic. |
| NET-028 | `TestNetDNSOddButValid/two questions` | Hide an allowed name in a second question. | RFC 1035 | Only the first question is answered. |
| NET-029 | `TestNetDNSOddButValid/answers, authorities and EDNS in the query` | Have the server echo records the query carries. | RFC 6891 | Nothing of the query but its first question is echoed. |
| NET-030 | `TestNetDNSOddButValid/the answer is never much larger than the query` | Use the proxy as an amplifier. | DNS amplification | An answer is at most 16 bytes longer than its query. |
| NET-031 | `TestNetDNSRandom` | Send 20,000 random packets and mutations of a valid query. | Fuzzing | No panic; any answer holds the proxy's address only. |
| NET-032 | `TestNetServeDNS/answers`, `/no answer to a response` | Make the server answer a response, for loops or reflection. | RFC 1035 | A query is answered; a response is not. |
| NET-033 | `TestNetServeDNS/a flood of malformed packets`, `/an oversize datagram`, `/a client gone before the answer` | Stop DNS with 3,000 junk packets, a 4 KB datagram, or a client whose port closes before its answers. | DNS denial of service | The server keeps answering. |
| NET-034 | `TestNetServeDNSThroughServe` | Find DNS missing from the served proxy. | Spec | `Serve` answers allowed names and refuses the others on its packet socket. |

### TLS toward the agent

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| NET-035 | `TestNetHandshakeAllowed`, 2 subtests | Get a certificate usable for more than one name, as a CA, or for long. | Spec: the run's CA constrained to the run's hosts | One exact DNS name, no address, URI or email, not a CA, server authentication only, at most 24 hours, one certificate sent, HTTP/1.1 negotiated. |
| NET-036 | `TestNetHandshakeRefusedNames`, 20 subtests | Get a handshake for another name, a case variant, a subdomain, a suffix or prefix, a wildcard, punycode, a percent-encoded or Cyrillic look-alike, a name with NUL, newline or spaces, `localhost`, a metadata name, or a 262-byte name. | Smokescreen [CVE-2022-24825](https://nvd.nist.gov/vuln/detail/CVE-2022-24825) and [CVE-2022-29188](https://nvd.nist.gov/vuln/detail/CVE-2022-29188), Traefik CVE-2026-48491 | Refused before any HTTP, with a `tls-server-name` line naming it, cut at 255 bytes; upstream never reached. |
| NET-037 | `TestNetHandshakeWireNames`, 7 subtests | Send on the wire what Go's client never would: an address, an IPv6 literal, a trailing dot, capitals, a NUL, or no name at all. | Smokescreen CVE-2022-29188, RFC 6066 | Refused; logged, except the trailing dot, which Go's parser refuses before any name is looked at. |
| NET-038 | `TestNetHandshakeFragmented`, 8 subtests | Split the ClientHello across 1-byte or 16-byte records and 1-byte TCP writes, as some filters fail to reassemble. | SNI filter evasion by fragmentation | The same decision as unfragmented: the allowed name is served, the other refused and logged. |
| NET-039 | `TestNetHandshakeVersions`, 4 subtests | Downgrade to TLS 1.0 or 1.1. | [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) | Refused; TLS 1.2 and 1.3 work. |
| NET-040 | `TestNetHandshakeWeakSuites`, 7 subtests | Offer only RC4, 3DES, static-RSA or CBC-SHA256 suites. | RFC 7465, Sweet32, Lucky13 | No handshake. |
| NET-041 | `TestNetALPN`, 8 subtests | Get HTTP/2, h2c, h3, `acme-tls/1` or HTTP/1.0 negotiated. | Spec: HTTP/1.1 only; [CVE-2023-44487](https://nvd.nist.gov/vuln/detail/CVE-2023-44487), [CVE-2024-27919](https://nvd.nist.gov/vuln/detail/CVE-2024-27919) | Only `http/1.1` or none is negotiated; a client offering nothing the proxy speaks gets no handshake. |
| NET-042 | `TestNetALPN/HTTP/2 preface over HTTP/1.1` | Send the HTTP/2 preface on an HTTP/1.1 connection. | RFC 9113 section 3.4 | Refused, upstream not reached. |
| NET-043 | `TestNetResumptionAcrossNames/TLS 1.3` | Resume, under the name `evil.example`, a TLS 1.3 session made for an allowed name: Go's server calls no `GetCertificate` on a resumed handshake. | [RFC 8446 section 4.6.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1), [Apache Traffic Server #13735](https://github.com/apache/trafficserver/issues/13735) | Refused: session tickets are off, so every handshake goes through the server-name check, and the refusal is logged. |
| NET-044 | `TestNetResumptionAcrossNames/TLS 1.2` | The same with TLS 1.2. | RFC 5077 | Refused: Go's TLS 1.2 server picks the certificate before resuming. |
| NET-045 | `TestNetHostAgainstServerName`, 11 subtests | On a connection for one allowed name, ask for another, first or pipelined, by `Host`, by port 443, by absolute form; or send no `Host`, two, an empty one, one with a userinfo, a trailing dot, capitals or port 80. | Traefik CVE-2026-48491 and CVE-2026-32305, Vercel's firewall | 403 or 400, and the other host's upstream is never reached. |
| NET-046 | `TestNetCertsConcurrent` | Race 64 handshakes for one name. | Race conditions in certificate caches | One certificate, no data race. |
| NET-047 | `TestNetCertsLifetime` | Get a leaf that outlives the run's CA. | Spec | The leaf ends no later than the CA, and starts before now. |
| NET-048 | `TestNetCertsRefusesWeakCA` | Start the proxy with a leaf, or a CA that cannot sign, as its CA. | Spec | Refused. |
| NET-049 | `TestNetServeRefusesIPv6Address` | Start the proxy with an IPv6 or mapped address to answer DNS with. | Spec: IPv4 only | Refused. |

### Toward upstreams

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| NET-050 | `TestNetUpstreamCertificates/valid`, `/wildcard for the host`, `/TLS 1.2 at most` | Find a valid upstream refused. | Spec | Served; the proxy sends the rule's host as the server name. |
| NET-051 | `TestNetUpstreamCertificates`, 14 refused subtests | Be an upstream with a certificate for another name or a parent, a wildcard two levels up, a common name only, an address only, expired or not yet valid, for client authentication or code signing only, from an untrusted CA, self-signed, outside its CA's name constraints, or speaking TLS 1.1 at most; or rely on the system roots. | [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525), Go's `x509` verification | 502 `upstream`, and the upstream handler never runs. |
| NET-052 | `TestNetUpstreamRedirects`, 30 subtests | Redirect with 301, 302, 303, 307 or 308 to the metadata service, another host, a scheme-relative URL, a userinfo trick, the IPv6 loopback, or the same host. | [CVE-2023-45289](https://nvd.nist.gov/vuln/detail/CVE-2023-45289), [CVE-2024-45336](https://nvd.nist.gov/vuln/detail/CVE-2024-45336) | The agent gets the status and `Location` as sent; the proxy makes one request and one connection. |
| NET-053 | `TestNetUpstreamSwitchingProtocols`, 2 subtests | Answer `101 Switching Protocols` to a request that asked for no upgrade, then send tunnel bytes. | Spec: no WebSocket; RFC 9110 section 15.2.2 | A 502: any status under 200 that reaches the proxy ends the exchange as an upstream refusal. |
| NET-054 | `TestNetUpstreamInformational`, 4 subtests | Send 103 Early Hints with a `Link` to another host, an unasked 100 or a 102, or 5,000 informational responses before the answer. | [RFC 8297](https://www.rfc-editor.org/rfc/rfc8297), [golang/go#65035](https://github.com/golang/go/issues/65035) | No 1xx header reaches the agent; the flood ends with 200 or 502, within the test's 10 seconds. |
| NET-055 | `TestNetUpstreamResponseHeaders/drops …`, 14 subtests | Pass hop-by-hop headers, headers named in `Connection` with odd spacing, case and repeats, `Set-Cookie` in any case, or `Alt-Svc`, to the agent. | [CVE-2021-33197](https://nvd.nist.gov/vuln/detail/CVE-2021-33197), RFC 9110 section 7.6.1 | Every one is dropped. |
| NET-056 | `TestNetUpstreamResponseHeaders/keeps …`, 4 subtests | Break the agent by dropping ordinary headers. | Spec | `Content-Type`, `ETag`, `Retry-After` and others pass. |
| NET-057 | `TestNetUpstreamHTTP2Headers` | The same over HTTP/2, with trailers. | RFC 9113 | `Alt-Svc`, `Set-Cookie`, `Trailer` and trailers never reach the agent. |
| NET-058 | `TestNetUpstreamHeaderSize`, 2 subtests | Answer with one 1 MiB header, or 20,000 headers, which the proxy holds and passes on. | [CVE-2023-45288](https://nvd.nist.gov/vuln/detail/CVE-2023-45288) and header bombs in general | A 502: upstream response headers are bounded at 64 KiB, as the agent's are. |
| NET-059 | `TestNetUpstreamMalformed`, 10 subtests | Answer with two different lengths, a negative or non-numeric one, an unknown encoding, no status line, an HTTP/2 status line, status 1000, a NUL or a bare CR in a value, or nothing. | [RFC 9112 section 6.3](https://www.rfc-editor.org/rfc/rfc9112#section-6.3) | 502. |
| NET-060 | `TestNetUpstreamMalformed/whitespace before a colon` | Send `Content-Length : 100` next to a chunked body, so a lenient agent reads another length. | [RFC 9112 section 5.1](https://www.rfc-editor.org/rfc/rfc9112#section-5.1) | Neither the odd header nor any `Content-Length` reaches the agent's socket. |
| NET-061 | `TestNetUpstreamMalformed/a length and chunked` | Send a length and chunked framing, with a smuggled response after the body. | RFC 9112 section 6.3, PortSwigger's request smuggling research | The agent reads the chunked body alone; the smuggled response never reaches it. |
| NET-062 | `TestNetUpstreamTruncated/with a length`, `/no length, no chunks` | Break off a body framed by its length, or by the connection's close. | [golang/go#23643](https://github.com/golang/go/issues/23643) | The agent sees the response fail, or, without framing, ends where the upstream ended. |
| NET-063 | `TestNetUpstreamTruncated/chunked`, `/chunked, inside a chunk`, `/HTTP/2 stream reset` | Break off a chunked body, or reset an HTTP/2 stream, in the middle. | [golang/go#23643](https://github.com/golang/go/issues/23643) | The connection to the agent is aborted, with no final chunk, so the truncation shows. |
| NET-064 | `TestNetUpstreamTrailersNeverCopied` | Send a secret in an HTTP/1.1 trailer. | Spec | The agent's socket holds neither the trailer nor its value. |
| NET-065 | `TestNetUpstreamBodiesUntouched` | Make the proxy decompress, through a gzip bomb or a body read differently. | Spec | No `Accept-Encoding` is added, and the gzip bytes pass as they are. |
| NET-066 | `TestNetUpstreamStalls`, 3 subtests | Stall before the headers or mid-body, or never speak TLS, to hold the proxy's goroutines and connections after the agent has left. | Slow upstreams | The upstream request is cancelled within 5 seconds of the agent leaving; the handshake ends with a 502. |
| NET-067 | `TestNetOneTransportPerHost` | Reuse an upstream connection made for one host for another. | Envoy CVE-2026-73548 | One connection per host, each dialed by its own name on 443. |
| NET-068 | `TestNetNoProxyFromEnvironment` | Route the upstream through `HTTPS_PROXY` or `ALL_PROXY`. | Spec | Ignored, for forwarded requests and for the proxy's own client. |
| NET-069 | `TestNetUpstreamClientNoRedirect` | Have the token client follow a redirect. | [CVE-2024-45336](https://nvd.nist.gov/vuln/detail/CVE-2024-45336) | It returns the 307 after one request, and has a timeout. |

### Limits and exhaustion

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| NET-070 | `TestNetServerSettings`, 20 subtests | Rely on a limit too long to wait for in a test: the 2-minute idle timeout, the 10-minute upstream wait, the handshake timeout; or find verification, HTTP/2 or an outbound proxy turned on. | [Envoy edge best practices](https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge) | Each setting is as the spec says. |
| NET-071 | `TestNetRequestSizeLimits`, 8 subtests | Send 70 KiB of headers, one 70 KiB header, a 70 KiB target or method, a 3000-byte path or query, a 10 KiB method, a non-ASCII header name. | RFC 6585, header bombs | 431, 403 or 400, and the upstream is never reached. |
| NET-072 | `TestNetRequestSizeLimits/obsolete line folding, never forwarded`, `/a bare LF, never forwarded`, `/5000 small headers, never forwarded`, `/100 small headers, all dropped` | Inject a header through line folding or bare LF, or flood headers that are not on the rule's list. | RFC 9112 section 5.2, request smuggling research | Go's server reads them, and none reaches the upstream: the request is rebuilt from the rule's headers. |
| NET-073 | `TestNetRequestFraming`, 12 table subtests | Send a chunk size that overflows or is not hex, 1 MiB of chunk extensions, odd `Transfer-Encoding` forms, both a length and chunked, two lengths, a signed length, trailers. | [CVE-2023-39326](https://nvd.nist.gov/vuln/detail/CVE-2023-39326), Squid CVE-2026-61642 | Refused, or read by its chunked framing alone and framed afresh upstream. |
| NET-074 | `TestNetRequestFraming/a request after a short length is checked like any other`, `/the G after length and chunked never reaches upstream` | Smuggle a second request after a body. | PortSwigger's request smuggling research | The second request is refused by the rules; the upstream gets one request with the declared body. |
| NET-075 | `TestNetBodyOverLimit`, 2 subtests | Stream a chunked body past 64 MiB, with no length to refuse it early, inspected or not. | Spec | 413 `too-large`, and the upstream never gets it whole. |
| NET-076 | `TestNetConnectionLimit` | Hold 256 connections open so that no other is served. | Slowloris | Connection 257 is not served; once one closes, it is. |
| NET-077 | `TestNetSlowClients`, 3 subtests | Hold a connection with no ClientHello, no request, or headers a byte every half second. | Slowloris | Closed after about 30 seconds each; the slow request never reaches the upstream. |
| NET-078 | `TestNetNoGoroutineLeak` | Leave 40 streamed answers in the middle. | Goroutine leaks | The goroutine count returns to where it was. |

### Audit log

| ID | Test | Attack | Source | Expected |
|---|---|---|---|---|
| NET-079 | `TestNetAuditOneLinePerDecision` | Make a decision go unlogged, or logged twice. | Spec | A refused handshake, an allowed request and a refused one are three lines, in order, with their reasons. |
| NET-080 | `TestNetAuditEscapes`, 10 subtests | Forge a log line, or act on the user's terminal, with a newline, CR LF, ANSI escape, NUL, invalid UTF-8, line separators, quotes, a newline in the method or `Host`, or a rune cut at 512 bytes. | [CWE-117](https://cwe.mitre.org/data/definitions/117.html) | One JSON line each, with no raw control byte. |
| NET-081 | `TestNetAuditEscapes/C1 CSI` and the C1 subtest of `TestNetAuditHandshakeNames` | Put U+009B, the one-character CSI, in a target or a server name. | [CWE-150](https://cwe.mitre.org/data/definitions/150.html) | Escaped as `\u009b`, as every C1 control is. |
| NET-082 | `TestNetAuditHandshakeNames`, 5 subtests | Forge lines or flood the log through the server name. | CWE-117 | One escaped line each, the name cut at 255 bytes. |
| NET-083 | `TestNetAuditLineBounded/a 60 KiB Host`, `/a 60 KiB method` | Write 60 KiB to the log with every refused request, through the `Host` or the method. | Log flooding | Every field bounded: the method at 32 bytes, the host at 255, the target at 512. |
| NET-084 | `TestNetAuditLineBounded/a 60 KiB target` | The same through the target. | Log flooding | The line stays under 2 KB. |
| NET-085 | `TestNetAuditNoSecrets/in the query`, `/in the path` | Send a real secret, learned from an upstream that echoes it, back in a target, so that it is written to the log, which outlives the run's secret files. | Spec: a line never holds a credential | The target is withheld from the log when it holds the placeholder or a secret, raw or percent-decoded. |
| NET-086 | `TestNetAuditNoSecrets/allowed, with the placeholder`, `/in a header`, `/in Authorization` | Get a credential in a header logged. | Spec | Never in the log. |
| NET-087 | `TestNetRefusalEchoesNothing` | Get a refusal to echo the request: markup, the placeholder, a long target, a header. | Squid [CVE-2025-62168](https://nvd.nist.gov/vuln/detail/CVE-2025-62168) | A fixed body under 64 bytes, `text/plain`, `Connection: close`. |

### Not tested here

- The 2-minute idle timeout, the 10-minute upstream wait and the 30-second upstream handshake timeout are pinned by `TestNetServerSettings` rather than waited out.
- A slow request body has no timeout, by design for uploads, and is bounded by the 256 connections.
- Real DNS rebinding through the system resolver: the transport's resolver cannot be injected, so `TestNetRebinding` stands in with a dialer whose addresses change between connections.
- TLS renegotiation: Go's server never renegotiates, and Go's client cannot start one, so testing it would need a TLS stack of its own.
- An SSLv2-compatible ClientHello, and a ClientHello with two server names: Go's parser refuses both; testing them would need hand-built handshakes.
- Spoofed DNS sources, and reflection off the proxy, need raw sockets.
- Azure's WireServer, `168.63.129.16`, is a public address: the deny list cannot name it without a cloud-specific rule. It serves on ports 80 and 32526, which the proxy never dials.

## Credentials and exfiltration
These tests are the credential part of the regression table that [the proxy](proxy.md#before-10) requires before 1.0. Each case is a hostile request a malicious plugin could send. It names the outcome the proxy must reach and what the upstream must or must not receive. Every subtest name starts with its ID. A case marked **limit** pins a channel the proxy cannot close and logs why.

The tests live in `internal/egress/creds_*_test.go`. `creds_rules_test.go` is an external test package: it builds the run's real rules with `proxy.Config` and drives them through the proxy against a recording upstream, using `CreUpstream` from `creds_export_test.go`.

### Credential headers

- **CRE-001** `TestCreHeaderForms/CRE-001_*`: the placeholder exactly as Claude Code (`Bearer`), the GitHub CLI (`token`) or `X-Api-Key` send it. Source: [docs/proxy.md](proxy.md#credentials). Expected: forwarded, with only the user's credential upstream.
- **CRE-002** `TestCreHeaderForms/CRE-002_*`: the attacker's own key in a lowercase, capital or mixed-case header name, after Go's parser canonicalizes the name. Source: [Claude Pirate, Rehberger](https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/). Expected: refused (`credential`).
- **CRE-003** `TestCreHeaderForms/CRE-003_*`: a scheme or placeholder in another letter case. Source: RFC 9110 §11.1 (schemes are case-insensitive to servers). Expected: refused (`credential`).
- **CRE-004** `TestCreHeaderForms/CRE-004_*`: two spaces, a tab or no space after the scheme, a scheme without a token, an empty value. Source: RFC 9110 §11.4. Expected: refused (`credential`).
- **CRE-005** `TestCreHeaderForms/CRE-005_*`: spaces or tabs around the value, which Go's parser trims. Expected: forwarded, since what remains is exactly the placeholder and it is dropped.
- **CRE-006** `TestCreHeaderForms/CRE-006_*`: the placeholder joined with a second scheme or token, prefixed, suffixed or doubled. Expected: refused (`credential`).
- **CRE-007** `TestCreHeaderForms/CRE-007_*`: Basic with the attacker's token or the placeholder, Digest, Negotiate, AWS SigV4. Expected: refused (`credential`).
- **CRE-008** `TestCreHeaderForms/CRE-008_*`: two `Authorization` headers in the same or another case (`header`), the placeholder alongside the attacker's API key (`credential`), a scheme inside `X-Api-Key` (`credential`).
- **CRE-009** `TestCreHeaderForms/CRE-009_*`: `Proxy-Authorization`, a claude.ai session cookie, `Private-Token`, `X-Goog-Api-Key`, `X-Goog-User-Project`, `X-Goog-Iam-Authorization-Token`, `X-Amz-Security-Token`, `X-Auth-Token`. Expected: refused (`credential`).
- **CRE-010** `TestCreHeaderForms/CRE-010_*`: `Connection` naming a credential header so a hop would drop or keep it. Source: CVE-2021-33197, CVE-2024-45410. Expected: refused (`header`).
- **CRE-011** `TestCreHeaderParser/CRE-011_*`: a space or tab before the colon, a folded line, a NUL in the name, a bare LF, a name without a colon. Expected: Go's parser refuses each. A line the parser accepts, such as a folded line it joins into one `X-Note` value, never becomes a credential the upstream reads.

### Placeholder and secrets anywhere else

- **CRE-012** `TestCreSecretPlacement/CRE-012_*`: the placeholder in a forwarded header, inside one, or in a header no rule forwards. Expected: refused (`credential`).
- **CRE-013** `TestCreSecretPlacement/CRE-013_*`: one of the user's real secrets in any header, including the credential headers. Expected: refused (`credential`).
- **CRE-014** `TestCreSecretPlacement/CRE-014_*`: the placeholder as a path segment, inside one, or as a query name. Expected: refused (`credential`).
- **CRE-015** `TestCreSecretPlacement/CRE-015_*`: a real secret in the path or query, including as `access_token`. Expected: refused (`credential`).
- **CRE-016** `TestCreSecretPlacement/CRE-016_*` (limit): the base64 or the reverse of a secret, or a credential of the agent's own, in a header a rule forwards. Expected: forwarded.
- **CRE-017** `TestCreSecretPlacement/CRE-017_*` (limit): a secret in a body that is not inspected, or in a Messages API body. Expected: forwarded.
- **CRE-018** `TestCreEncodedSecretInQuery/CRE-018_*` a real secret or the placeholder with percent-escapes in the query. The upstream decodes the escapes, so the proxy searches the decoded query as well as the raw target. Source: [docs/proxy.md](proxy.md#credentials), "one of the user's real secrets anywhere in the request refuses it". Expected: refused (`credential`).
- **CRE-019** `TestCreOnlyTheProxysCredential/CRE-019_*`: a bearer placeholder sent to an API-key rule, or the placeholder sent to a rule with no credential. Expected: forwarded, with exactly the rule's credential upstream and nothing in the other header.
- **CRE-020** `TestCreOnlyTheProxysCredential/CRE-020_*`: method overrides (`X-Http-Method-Override` and variants), forwarding headers (`X-Forwarded-*`, `Forwarded`, `X-Original-Url`), `X-Github-Otp`, Anthropic key look-alikes. Expected: forwarded as `GET`, with every one of these headers dropped.

### Claude's server-side tools

- **CRE-021** `TestCreServerTools/CRE-021_*`: every documented `web_fetch` and `code_execution` version, plus `bash_code_execution` and `text_editor_code_execution`. Source: [tool reference](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-reference). Expected: refused (`server-tool`).
- **CRE-022** `TestCreServerTools/CRE-022_*`: an MCP toolset, `mcp_servers` as an array or an object (`server-tool`), and an empty `mcp_servers` (forwarded). Source: [MCP connector](https://platform.claude.com/docs/en/agents-and-tools/mcp-connector).
- **CRE-023** `TestCreServerTools/CRE-023_*`: Unicode escapes in a type, a type key or a tools key (`server-tool`), and keys repeated through escapes, case or nesting (`body`).
- **CRE-024** `TestCreServerTools/CRE-024_*`: `tools` as an object, a tool as a string, a type as a number or an object. Expected: refused (`body`).
- **CRE-025** `TestCreServerTools/CRE-025_*` (limit): a tool type in capitals or with a leading space, a lone `Tools` key, a `tools` key with a NUL. Expected: forwarded. The API matches types and keys exactly and refuses unknown ones.
- **CRE-026** `TestCreServerTools/CRE-026_*`: Claude Code's own tools, a null type, `web_search_20250305` with or without `allowed_domains` (limit: its queries reach the search provider only), tool search, and the advisor (limit: a model on Anthropic's side). Expected: forwarded.
- **CRE-027** `TestCreServerTools/CRE-027_*`: the client tools `memory`, `bash`, `text_editor`, `computer`, `computer_toolset` and `browser_toolset`, which run on the agent's side. Expected: forwarded.
- **CRE-028** `TestCreWebSearchRunsCode/CRE-028_*` `web_search_20260209` and `web_search_20260318` default `allowed_callers` to code execution ("dynamic filtering"), so Anthropic's servers would run code the proxy refuses when asked by name. Source: [web search tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool). Expected: refused (`server-tool`), unless `allowed_callers` is `["direct"]`.

### Content Anthropic's servers fetch

- **CRE-029** `TestCreURLSources/CRE-029_*` an image or a PDF with `"source":{"type":"url"}`, in a user message, in a `tool_result`, in an earlier turn, or with an escaped `url` type. Anthropic's servers would fetch the URL, which can carry the user's data to the attacker's server through the user's own account. Source: [vision](https://platform.claude.com/docs/en/build-with-claude/vision), [PDF support](https://platform.claude.com/docs/en/build-with-claude/pdf-support), [Messages API reference](https://platform.claude.com/docs/en/api/messages/create). Expected: refused.
- **CRE-030** `TestCreURLSources/CRE-030_*`: a base64 image, a text document whose data is a URL, a text block naming a URL. Expected: forwarded, since none of them is fetched.
- **CRE-031** `TestCreURLSources/CRE-031_*` (limit): a Files API file ID, a container upload, skills without code execution, a `server_tool_use` block in the history. Expected: forwarded. None of them runs or reaches out without a tool or endpoint the proxy refuses. Source: [Files API](https://platform.claude.com/docs/en/build-with-claude/files), [skills](https://platform.claude.com/docs/en/build-with-claude/skills-guide).

### JSON parser differentials

- **CRE-032** `TestCreJSONDifferentials/CRE-032_*`: BOM, line and block comments, trailing commas, NaN, Infinity, single quotes, unquoted keys, a raw NUL or newline, a number too large for a double, a 400-digit integer. Expected: refused (`body`).
- **CRE-033** `TestCreJSONDifferentials/CRE-033_*`: trailing garbage, a second value, a top-level array, string or number (`body`), a top-level `null` (`body`), and trailing whitespace (forwarded).
- **CRE-034** `TestCreJSONDifferentials/CRE-034_*`: 120 levels of nesting (forwarded), 200 levels of arrays and 300 of objects (`body`).
- **CRE-035** `TestCreJSONDifferentials/CRE-035_*`: a key repeated through an escape inside a content block (`body`), and a key with a long s (limit: no parser folds it).
- **CRE-036** `TestCreInvalidUTF8/CRE-036_*` invalid UTF-8 or an overlong encoding in a key, a tool type or a source type. Go would read it as U+FFFD while the raw bytes are forwarded, so the proxy would decide on one reading and the API get another. Source: [docs/proxy.md, the principle](proxy.md#the-principle). Expected: refused (`body`).
- **CRE-037** `TestCreMessagesFraming/CRE-037_*`: a server tool in a chunked body (`server-tool`), a gzip body (`body`), `count_tokens` with `web_fetch` (`server-tool`), and bodies past 64 MiB, chunked or declared (`too-large`). Also `count_tokens` with a URL image (`server-tool`, as CRE-029). `TestCreMessagesNoBody` checks that a request with no body forwards no body.

### DNS

- **CRE-038** `TestCreDNS/CRE-038_*`: data in the labels of an allowed name, labels of 63 bytes, the attacker's name, an allowed name as a prefix of the attacker's. Source: [CVE-2025-55284](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/). Expected: NXDOMAIN, never forwarded.
- **CRE-039** `TestCreDNS/CRE-039_*`: TXT, MX, CNAME, SRV, ANY, NS, HTTPS and PTR queries. Expected: no record but the proxy's A for an allowed name, and NXDOMAIN for any other name.
- **CRE-040** `TestCreDNS/CRE-040_*`: the CHAOS class, update and notify opcodes. Expected: NOTIMP.
- **CRE-041** `TestCreDNS/CRE-041_*`: EDNS with a large buffer and a client cookie, and 0x20 case. Expected: an answer with no OPT, no additional or authority record, and no larger than the question allows.
- **CRE-042** `TestCreDNS/CRE-042_*`: a response, no question, a truncated name, a pointer loop, garbage. Expected: no answer.
- **CRE-043** `TestCreDNSServeAnswersAlone`: the DNS server on a real socket answers the attacker's TXT queries itself, with NXDOMAIN.

### The run's real rules

- **CRE-044** `TestCreRulesGitHubToken/CRE-044_*`: reads of the run's repository. Expected: forwarded with the user's token, and the agent's method override dropped.
- **CRE-045** `TestCreRulesGitHubToken/CRE-045_*`: the owner or repository in another letter case (the same repository to GitHub), `.git`, near names, another owner, the owner alone, the API root. Expected: forwarded anonymously, with no `Authorization` upstream.
- **CRE-046** `TestCreRulesGitHubToken/CRE-046_*` (limit): a compare across forks under the run's repository, which is read with the token, and the agent's own token in the query of an anonymous read. Expected: forwarded.
- **CRE-047** `TestCreRulesGitHubToken/CRE-047_*`: git fetches of the run's repository, including a protocol v2 `ls-refs`, with or without `.git`. Expected: forwarded with Basic `x-access-token`, and the body unchanged.
- **CRE-048** `TestCreRulesGitHubToken/CRE-048_*`: raw content of the run's repository, and raw paths carrying data (limit). Expected: forwarded with no credential.
- **CRE-049** `TestCreRulesClaudeCredential/CRE-049_*`: subscription and API-key runs on `/v1/messages`, `count_tokens` and the policy endpoint, with the placeholder in both credential headers. Expected: the user's credential in its one header, nothing in the other.
- **CRE-050** `TestCreRulesVertexToken/CRE-050_*`: Vertex `streamRawPredict` and `count-tokens:rawPredict` in the user's project, with `X-Goog-Request-Params` naming another project. Expected: the minted token, and no `X-Goog-*` or override header upstream.
- **CRE-051** `TestCreRulesVertexToken/CRE-051_*` (limit): another method, such as `:generateContent`, on an Anthropic model. Expected: forwarded, still in the user's project and region, and inspected.
- **CRE-052** `TestCreRulesGitHubWrites/CRE-052_*`: pull requests, issues, comments, file writes, ref updates, a repository deletion, gists, GraphQL, the user's profile, a push's ref advertisement and a push, a fetch of another repository, a POST to raw content (`no-rule`), and the uploads host (`host`). The push happens on the host, after the user's review. Expected: refused, nothing upstream.
- **CRE-053** `TestCreRulesAnthropicEndpoints/CRE-053_*`: the Files API, message batches, skills, models, an admin endpoint, OAuth, another query or a second query parameter on the Messages API, a GET on it, a write to the policies (`no-rule`), the console, claude.ai, and Anthropic's API in a Vertex run (`host`). Expected: refused, nothing upstream.
- **CRE-054** `TestCreRulesVertexScope/CRE-054_*`: another project, another region in the path, another publisher, `v1beta1`, a deeper path, any query including a key, a GET on the model, the project's endpoints (`no-rule`), another region's host, the global host, Cloud Storage, Google's token endpoint (`host`), and a URL image sent to Vertex (`server-tool`). Expected: refused, nothing upstream.

### Channels the proxy cannot close

- **What the model sees**: data the plugin puts in a Messages request reaches the user's own account. Web search queries reach Anthropic's search provider, which the attacker cannot read (CRE-026, CRE-017).
- **Encodings of a secret**: base64, reversed or split secrets cannot be recognized in general. The agent never holds a real secret, so it has none to encode (CRE-016).
- **Credentials in forwarded headers and queries**: the proxy cannot recognize every token format in a header a rule forwards, or in the query of an `AnyQuery` rule. The services the rules reach do not read a credential there; GitHub no longer accepts `access_token` (CRE-016, CRE-046).
- **Bodies**: bodies other than the Messages API pass untouched (CRE-017).
- **Anonymous read paths**: the paths of anonymous GitHub API reads and raw reads are the agent's choice. Sealroom relies on GitHub not showing those reads to the content's owner, as the threat model says (CRE-048).
- **Cross-fork reads**: a read under the run's repository can name a fork of the same network with the user's token. It reads only what the user can read (CRE-046).
- **Vertex methods**: any method on an Anthropic model in the user's project passes. It never leaves the user's project or region (CRE-051).
- **Unknown tool types and keys**: a type or key the proxy does not know is forwarded; the API refuses it (CRE-025, CRE-033, CRE-035).
- **Declared hosts**: a host the user accepts from the plugin's declaration receives whatever the plugin sends there, with no credential of the user's.

### Sources

- [Claude Pirate: the Anthropic Files API with an attacker's key](https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/), and [the same attack on Claude Cowork](https://promptarmor.com/resources/claude-cowork-exfiltrates-files).
- [CVE-2025-55284, DNS exfiltration in Claude Code](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/).
- [CVE-2026-21852, ANTHROPIC_BASE_URL in project files](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/): a host the rules do not name is refused at the handshake, and the agent holds only the placeholder.
- [CamoLeak](https://legitsecurity.com/blog/camoleak-critical-github-copilot-vulnerability-leaks-private-source-code), [Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/), [GitLost](https://noma.security/noma-labs/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos), [the GitHub MCP toxic flow](https://invariantlabs.ai/blog/mcp-github-vulnerability): channels through GitHub image proxies and writes, hosts and methods the rules do not allow.
- [CVE-2026-54316, HuggingFace download counters](https://www.wiz.io/vulnerability-database/cve/cve-2026-54316): a counter as a covert channel; the host is not allowed.
- [Claude's Messages API reference](https://platform.claude.com/docs/en/api/messages/create), [the tool reference](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-reference), [web search](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool), [vision](https://platform.claude.com/docs/en/build-with-claude/vision), [PDF support](https://platform.claude.com/docs/en/build-with-claude/pdf-support), [Claude on Vertex AI](https://platform.claude.com/docs/en/build-with-claude/claude-on-vertex-ai).

## A hostile plugin, end to end
This is the catalogue behind `TestHostile` in `internal/e2e/hostile_test.go`.

`TestHostile` runs whole sealed sessions with a deliberately hostile stand-in for Claude Code, built from the real agent image in `internal/e2e/testdata/hostile/`, so the attempts run as a plugin's code runs: as the agent's user (uid 10001), with no capabilities, a read-only root, an internal network whose only exit is the proxy, and placeholders where credentials would be.

The stand-in writes one result line per attempt into the repository, so the results come back to the host in the session's patch, where the test asserts each one. Three sessions run: `probe` (the full catalogue, plus a hostile-but-valid pull request), `symlink` (a planted link where the review reads a regular file), and `hugepatch` (a patch larger than the review will read).

Every attempt's expected outcome is containment. If an attempt ever succeeds where it should not, the matching assertion stays failing on purpose: that is a finding, not a test to weaken.

The design this exercises is in [the proxy](proxy.md), [the design](design.md) and [the threat model](threat-model.md). The unit layer already covers the review's own checks (symlink refusal, size limits, sanitisation, branch fallback, and `.git`-path refusal) in `internal/review/review_test.go`; these end-to-end entries prove the same holds when the real sealed agent plants the input through the real pipeline, and add the container and network layer that exists only end to end.

### Egress and routing: no way out but the proxy

E2E-001 — HTTPS to an arbitrary external host (`https://exfil.attacker.example/`).
Source: egress-proxy allow-listing; [preventing SSRF in Go](https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang); [data exfiltration through the Anthropic API](https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/).
Expected: the name does not resolve; curl cannot connect.
Checked: `egress-arbitrary-https=000` in the patch.

E2E-002 — Plain HTTP to an arbitrary external host (`http://exfil.attacker.example/`).
Source: the same, plus the proxy's HTTPS-only listener in [proxy.md](proxy.md).
Expected: the name does not resolve, and there is no plain-HTTP route anyway.
Checked: `egress-plain-http=000`.

E2E-003 — HTTPS straight to a raw public IP (`https://1.1.1.1/`), skipping DNS.
Source: SSRF by literal address; the proxy's dial-time address checks in [proxy.md](proxy.md).
Expected: the internal network has no route to any address but the proxy.
Checked: `egress-raw-ip-https=000`.

E2E-004 — HTTPS to a raw IPv6 address (`https://[2606:4700:4700::1111]/`).
Source: IPv6 egress bypasses; Go's IPv4-mapped address flaw, CVE-2024-24790, cited in [proxy.md](proxy.md).
Expected: there is no IPv6 route out.
Checked: `egress-ipv6=000`.

E2E-005 — Plain HTTP to the proxy's own address on port 80.
Source: the proxy has no plain-HTTP listener ([proxy.md](proxy.md)).
Expected: nothing listens on port 80; the connection is refused.
Checked: `egress-http-to-proxy=000`.

E2E-006 — HTTPS to the proxy's own address on another port (`:8443`).
Source: the proxy serves HTTPS on 443 only, and no port ever comes from a request ([proxy.md](proxy.md)).
Expected: nothing listens on the other port.
Checked: `egress-proxy-alt-port=000`.

E2E-007 — Raw `bash` `/dev/tcp` to the proxy on port 22, and E2E-008 on port 8080.
Source: raw-socket egress and port scanning of the one reachable peer.
Expected: only the proxy's service ports answer; these are refused.
Checked: `tcp-proxy-ssh=blocked`, `tcp-proxy-http=blocked`.

E2E-009 — Raw `/dev/tcp` to the network's gateway address (the `.1` of the subnet) on 443.
Source: container-to-host reachability through the bridge gateway; [Claude Code container sandbox-escape CVEs](https://bex.co/blog/2026/09/25/claude-code-cves-container-sandbox-escape).
Expected: the network is internal, with no gateway that routes out.
Checked: `tcp-gateway=blocked`.

E2E-010 — Raw `/dev/tcp` to the cloud metadata address `169.254.169.254:80`.
Source: link-local metadata SSRF ([OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)); link-local is in the proxy's refused-address list ([proxy.md](proxy.md)).
Expected: link-local has no route from the internal network.
Checked: `tcp-metadata=blocked`.

E2E-011 — Raw `bash` `/dev/udp` to an external resolver (`8.8.8.8:53`) for UDP exfiltration.
Source: UDP and DNS-over-UDP exfiltration out of band.
Expected: there is no UDP route out.
Checked: `udp-external-dns=blocked`.

### DNS carries nothing out

E2E-012 — Resolve an exfiltration-shaped name (`<base64>.exfil.attacker.example`).
Source: DNS tunnelling and exfiltration (iodine/dnscat class); the proxy forwards no query ([proxy.md](proxy.md)).
Expected: only the run's own hosts resolve; this one does not exist.
Checked: `dns-exfil=unresolved`.

E2E-013 — Resolve `host.docker.internal`, and E2E-014 `host.containers.internal`.
Source: Docker and Podman host aliases as a path back to the host. Rootless Podman writes both into the container's `/etc/hosts`, where they resolve to the host without any DNS query; CI found it with this test.
Expected: they do not resolve: the agent's `/etc/hosts` is the run's own, mounted read-only, naming localhost alone, and the proxy answers DNS for the run's allowed names only.
Checked: `dns-host-docker-internal=unresolved`, `dns-host-containers-internal=unresolved`, and E2E-052.

E2E-015 — Resolve `metadata.google.internal`.
Source: cloud metadata by name ([OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)).
Expected: it does not resolve.
Checked: `dns-metadata=unresolved`.

E2E-052 — Find any other name the container runtime wrote into `/etc/hosts`.
Source: runtime-managed `/etc/hosts` entries, as E2E-013 and E2E-014 found with rootless Podman.
Expected: none: only `localhost`, for 127.0.0.1 and ::1.
Checked: `hosts-entries=0`.

E2E-016 — Resolve an allowed host (`api.anthropic.com`) as a positive control.
Source: this fixture, to show DNS is not simply broken.
Expected: an allowed name resolves, and only to the proxy's address.
Checked: `dns-allowed-control=resolved`.

### Identity, credentials and secrets

E2E-017 — Read the process's user id.
Source: non-root containers; [the design](design.md).
Expected: the agent is a non-root user.
Checked: `uid=10001`.

E2E-018 — Read the process's effective capabilities from `/proc/self/status`.
Source: `--cap-drop ALL`; [the design](design.md).
Expected: no capability is held.
Checked: `caps=CapEff:0000000000000000`.

E2E-019 — Count credential-shaped environment variables, and E2E-020 how many hold only the placeholder.
Source: a plugin that reads every variable finds nothing usable ([threat model](threat-model.md)); [API-key exfiltration before the trust prompt (CVE-2026-21852)](https://bex.co/blog/2026/09/25/claude-code-cves-container-sandbox-escape).
Expected: every credential variable holds the placeholder.
Checked: `credential-vars=2` and `placeholders=2` (equal).

E2E-021 — Scan the environment for anything secret-shaped (`sk-ant-`, `ghp_`, AWS keys, PEM private keys), excluding the placeholder.
Source: secret scraping from the process environment.
Expected: no real secret is present.
Checked: `real-secrets-env=0`.

E2E-022 — Read the run's CA private key at `/etc/sealroom/ca.key`, and E2E-023 the proxy's config at `/etc/sealroom/proxy.json`.
Source: reaching the proxy's own files from the agent; [the design](design.md) mounts only the CA certificate into the agent.
Expected: neither is present in the agent container.
Checked: `ca-key-readable=no`, `proxy-config-readable=no`.

E2E-024 — Look for a container-runtime socket (`/var/run/docker.sock`, `/run/docker.sock`, Podman's socket).
Source: the Docker/Podman socket as a host-takeover primitive; [container sandbox-escape CVEs](https://bex.co/blog/2026/09/25/claude-code-cves-container-sandbox-escape).
Expected: no runtime socket is mounted.
Checked: `docker-socket=absent`.

### The proxy is the only credentialed exit

E2E-025 — POST the Messages API with the placeholder credential and an ordinary request.
Source: the proxy swaps the placeholder for the real credential last ([proxy.md](proxy.md)).
Expected: the request reaches Anthropic, which rejects the fake credential the proxy added.
Checked: `model-placeholder=401` (the service's own 401, so the request was forwarded with a credential the agent never held).

E2E-026 — POST the Messages API with a bearer token of the agent's own (`sk-ant-attacker-key`).
Source: exfiltration through the Anthropic API with the attacker's key ([embracethered](https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/)).
Expected: a credential that is not the placeholder is refused by the proxy.
Checked: `model-own-key=403`.

E2E-027 — POST the Anthropic Files API with the placeholder.
Source: storing data on the provider for later retrieval; the Files API is refused ([proxy.md](proxy.md), [threat model](threat-model.md)).
Expected: no rule allows it.
Checked: `files-api=403`.

E2E-028 — POST the Messages API with the placeholder but a body carrying `mcp_servers`, to make Anthropic's servers connect out.
Source: server-side tools (`web_fetch`, code execution, MCP) as a side channel ([proxy.md](proxy.md)); [the first malicious MCP server, postmark-mcp](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html).
Expected: the proxy inspects the Messages body and refuses a server-side tool.
Checked: `server-side-tool=403`.

### GitHub: reads, on the run's repository only

E2E-029 — GET the run's repository through the API.
Source: the user's token is added only to reads of the run's repository ([proxy.md](proxy.md)).
Expected: the request carries the user's token (here a fake one, so the service answers 401).
Checked: `run-repo-read=401`.

E2E-030 — GET another repository with a token of the agent's own.
Source: smuggling the attacker's own credential past the allow-list.
Expected: a non-placeholder credential header is refused.
Checked: `other-repo-own-token=403`.

E2E-031 — POST an issue, E2E-032 a GraphQL query, and E2E-033 a gist.
Source: pushing data to GitHub as the exfiltration channel ([threat model](threat-model.md)); GraphQL is refused outright ([proxy.md](proxy.md)).
Expected: GitHub writes and the GraphQL endpoint are refused.
Checked: `github-write-issue=403`, `github-graphql=403`, `github-gist=403`.

E2E-034 — Git-fetch another repository's refs, and E2E-035 POST a `git-receive-pack` (a push) to another repository with an embedded token.
Source: pushing code to a repository of the attacker's ([threat model](threat-model.md)).
Expected: only the run's repository may be fetched, and no push is allowed.
Checked: `other-git-fetch=403`, `attacker-git-push=403`.

### Resource limits

E2E-036 — Read the container's pid limit, and E2E-037 its memory limit, from the cgroup.
Source: process and memory limits ([the design](design.md)); fork bombs and memory exhaustion.
Expected: the limits are the configured ones; the kernel enforces them, so a fork bomb cannot harm the host and is not run live (a live fork bomb would only starve the session's own pid budget).
Checked: `pids-max=512`, `memory-max=4294967296`.

E2E-038 — Attempt an unbounded allocation inside a child capped by `ulimit -v`, so the growth cannot touch the host.
Source: memory exhaustion, bounded by limits.
Expected: the over-limit allocation is denied.
Checked: `mem-overlimit=blocked`.

### Nothing writes to the host but the output directory

E2E-039 — Write to `/etc`, E2E-040 to `/usr`, and E2E-041 to the mounted repository at `/src`.
Source: a read-only root and read-only mounts ([the design](design.md)).
Expected: every write is refused.
Checked: `write-etc=blocked`, `write-usr=blocked`, `write-repo-mount=blocked`.

E2E-042 — Write to `/proc/sysrq-trigger`, and E2E-043 to a cgroup `release_agent`.
Source: `/proc` and cgroup-v1 `release_agent` host escapes (CVE-2022-0492); [container sandbox-escape CVEs](https://bex.co/blog/2026/09/25/claude-code-cves-container-sandbox-escape).
Expected: both are masked or read-only, and the agent has no privilege for them.
Checked: `write-proc-sysrq=blocked`, `cgroup-release-agent=blocked`.

E2E-044 — Write to the output directory, as a control.
Source: this fixture, to show the output directory is the one host-visible writable path.
Expected: the write succeeds; this is the only channel to the host, reviewed afterward.
Checked: `out-writable=yes`.

E2E-045 — Make a device node in the output directory (`mknod`), and E2E-046 a hard link there to the mounted CA certificate.
Source: planting special files and hard links for the host review to mishandle; hostile output in [the design](design.md).
Expected: `mknod` needs a capability the agent does not have, and a hard link cannot cross the mount boundary.
Checked: `mknod-device=blocked`, `hardlink-ca=blocked`.

### Hostile output for the host review

E2E-047 — Create a FIFO in the output directory.
Source: special files left for the host's cleanup and review to choke on.
Expected: the FIFO is created, the review reads only the files it names (so it ignores it), and the cleanup still empties the directory.
Checked: `fifo-created=yes`, and the test asserts the output directory is empty after the review.

E2E-048 — Record a pull request whose title, body and commit message carry terminal escape sequences and a right-to-left override.
Source: terminal-escape and bidirectional-text injection into what the user reviews; sanitisation in [the design](design.md) and `internal/review/sanitize.go`.
Expected: everything shown is rendered as text; no raw escape or direction-changing byte reaches the terminal.
Checked: the review's output contains `\x1b[8m`, `\x1b[2J`, `‮` and `\x1b[31m`, and contains no raw `0x1b` or `U+202E`.

E2E-049 — Record a pull-request base that looks like a command-line option (`--web`).
Source: slipping an option into the push or the pull request ([threat model](threat-model.md)); every session value reaches `gh` as one `--flag=value` argument, and the publish layer is unit-covered.
Expected: the base is shown as literal text, acted on by nothing in the review.
Checked: the review shows `Base:  --web`, and the branch is kept (no `gh` call: `noGitHub` fails the test if the review calls GitHub).

E2E-050 — Plant the pull request's body as a symbolic link to a file of the host's (`/etc/passwd`).
Source: a link the agent plants, to a key or a secret of the host's, that the review must never follow ([threat model](threat-model.md)); `internal/review/output.go`.
Expected: the review refuses any output file that is not a regular file, and never follows the link.
Checked: in the `symlink` session, `launcher.Review` returns an error containing "not a regular file", nothing reaches GitHub, and the output directory is emptied.

E2E-051 — Produce a patch larger than the review will read (17 MiB, above the 16 MiB limit).
Source: enormous outputs; the patch size limit in `internal/review/output.go`.
Expected: the patch is refused whole, never truncated, so nothing beyond the limit reaches the host.
Checked: in the `hugepatch` session, `launcher.Review` returns an error containing "larger than", and the output directory is emptied.

### Attempts not made, and why

ICMP (`ping`): no `ping` binary is installed, and ICMP needs `CAP_NET_RAW`, which is dropped; the internal network has no route out regardless, which E2E-003 and E2E-010 already show.
DNS record types other than A/AAAA (TXT, etc.) and queries to a chosen external resolver: no `dig`/`nslookup`/`host` is installed, and there is no route to an external resolver (E2E-011); the proxy forwards no query (E2E-012).
A raw patch touching a `.git` directory: the session's patch is generated by the session script with `git format-patch`, and git never tracks `.git`, so the agent cannot inject arbitrary patch bytes through this pipeline; the `.git`-path refusal is unit-covered in `internal/review/review_test.go` (`TestApplyRefusesGitDirectory`).
A branch name that is a command-line option: git will not create a ref beginning with a dash, and the review validates the branch and falls back otherwise; this is unit-covered (`TestApplyFallsBackForBadBranches`).
A live fork bomb: the pid cgroup limit (E2E-036) is the control and is kernel-enforced, so running one would only risk the session's own pid budget without adding assurance; see the note there.

### Sources

- Anthropic API data exfiltration with an attacker's key — https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/
- The first malicious MCP server in the wild (postmark-mcp, September 2025) — https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html and https://www.bleepingcomputer.com/news/security/unofficial-postmark-mcp-npm-silently-stole-users-emails/
- Claude Code container sandbox-escape CVEs, including API-key exfiltration before the trust prompt — https://bex.co/blog/2026/09/25/claude-code-cves-container-sandbox-escape
- The vm2 sandbox-escape CVE wave and why isolation belongs at the kernel layer — https://www.kodemsecurity.com/resources/vm2-sandbox-escape-vulnerabilities-the-2026-cve-wave-turning-ai-agents-into-host-rce-vectors
- Preventing SSRF in Go (dial-time address checks) — https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang
- OWASP Server-Side Request Forgery (link-local and cloud metadata) — https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- cgroup-v1 `release_agent` container escape, CVE-2022-0492 — https://nvd.nist.gov/vuln/detail/CVE-2022-0492
- Sealroom's own specification: [the proxy](proxy.md), [the design](design.md), [the threat model](threat-model.md), and the proxy's own source advisories listed in [proxy.md](proxy.md).
