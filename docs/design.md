# Design

This document describes how Sealroom works and why. Every decision below is judged by one question: does it make Sealroom easier to trust?

## The one-sentence design

> The plugin runs in a container that has no way out but a proxy, the proxy holds every credential, and nothing leaves the run before the user reviews it.

## What a run looks like

```
sealroom run <plugin> --repo <owner/repo>
```

1. On the host, Sealroom clones the repository and prepares the run.
2. It starts two containers: the **agent**, where Claude Code runs with the plugin, and the **proxy**, the agent's only way out.
3. The user works with Claude Code interactively, exactly as on their own machine: prompts, menus, the plugin's commands.
4. When the session ends, Sealroom shows on the host what the run changed and the pull request it prepared.
5. On the user's yes, Sealroom pushes the branch and opens the pull request with the user's own GitHub login. On no, nothing leaves.

## Components

| Component | Runs where | Does |
|---|---|---|
| **Launcher** (`sealroom`) | The user's machine | Clones the repository, writes the proxy's rules for this run, hands the credentials to the proxy only, starts both containers, and after the session shows the changes and pushes on the user's yes |
| **Agent container** | Container runtime | Claude Code, the plugin mounted read-only, a copy of the repository, and stand-ins for `git push` and `gh pr create` |
| **Proxy container** | Container runtime | The only route out of the agent: allows each request by host, method and path, holds the credentials and adds them to allowed requests, refuses everything else |

The launcher drives Podman or Docker directly, Podman first when both are installed. It does not depend on Compose, whose command and behaviour differ between Docker's plugin, the standalone binary and Podman.

## The run directory

Each run gets a directory under the user's cache directory (`~/.cache/sealroom/runs` on Linux, `~/Library/Caches/sealroom/runs` on macOS). It is under the home directory, so a runtime in a virtual machine that shares only the home directory, as on macOS, can mount it. Only the user can enter it. It holds the clone, the proxy's rules, the run's CA and the proxy's credentials file, and the output directory. The files the proxy reads are readable by all, since the proxy runs as its own user, but the directory around them is the user's alone. The credentials file is readable by the user only: the runtime's command line reads it on the proxy's behalf. The output directory is writable by the agent's user.

The launcher creates the internal network on a random private subnet, starts the proxy and waits until it listens, then attaches the agent to the user's terminal. Ctrl-C belongs to the session while it runs. When the session ends, however it ends, the launcher removes the proxy and both networks.

## The agent container

| Restriction | Why |
|---|---|
| Internal network only: no gateway, and DNS answered by the proxy | Nothing reaches the internet except through the proxy. Raw sockets, hard-coded addresses and DNS tunnels have no route |
| Non-root user, all capabilities dropped, `no-new-privileges` | No privilege to gain, and nothing that could change the network rules |
| Read-only root filesystem, throwaway home and work directory in memory | The plugin cannot alter the tooling, and nothing persists after the run |
| Nothing from the host mounted, except the plugin read-only, the repository read-only, the proxy's CA certificate, and one output directory | No home directory, no keys, no credentials, no container runtime socket |
| No credential of any kind, only placeholders | A plugin that reads every file and every environment variable finds nothing usable |
| Memory, CPU, process and time limits | A plugin cannot exhaust the machine |

The proxy container is locked down the same way: read-only root, no capabilities, `no-new-privileges`, the same limits, and only its configuration, the CA certificate and key mounted, read-only. It answers DNS and HTTPS on low ports through the `ip_unprivileged_port_start` setting of its own network namespace, not a capability. Its credentials arrive in an environment file that only the proxy receives.

Both containers start with `--pull never`, so a run never reaches a registry. The restrictions are set in one place, `internal/sandbox`, and `TestArgsSeal` fails if one goes missing or a forbidden option appears, such as `--privileged`, an added capability, a host namespace, a published port, or an extra mount. A host path mounted into a container is refused if it is not absolute and clean, if it is the root, the home directory or one of its parents, or if it contains a character that would change the meaning of the mount option. The agent receives only a fixed list of environment variables, and every credential variable must hold the placeholder.

The image holds Claude Code, git and the GitHub CLI, each downloaded at a pinned version and checked against a checksum in the image's definition, on a Debian base pinned by digest. Claude Code follows its stable channel, with its auto-updater and non-essential traffic turned off, and its first-run screens skipped. The stand-ins for `git` and `gh` come first on the `PATH`, ahead of the real commands.

The repository is copied into the container at start, so the plugin never writes to the user's clone. The output directory receives the changes as a patch, the branch name, and the recorded pull request, and nothing else is written on the host. When Claude Code exits, the session script commits whatever is left uncommitted and writes every commit since the repository's default branch as one patch.

## The proxy

The proxy is [iron-proxy](https://github.com/paradigmxyz/iron-proxy), an egress firewall built for untrusted workloads. It intercepts TLS with a CA created for the run, so it sees each request's host, method, path and headers.

Sealroom does not use its published images or binaries, which are not signed. It builds the proxy from a release commit whose signature was verified when it was pinned, on a minimal base image pinned by digest, with Go modules checked against iron-proxy's `go.sum`. The image, in `images/proxy`, runs as a non-root user and holds nothing but the proxy's static binary.

### What each credential can do

| Destination | Allowed | Credential added by the proxy |
|---|---|---|
| Anthropic API | `POST` to the model endpoints, and Claude Code's read-only policy endpoints | The user's Claude credential, only in place of the agent's placeholder. A request without the placeholder is refused, so a plugin's own key never gets through |
| Google Vertex AI | `POST` to the model endpoints of the user's project and region | An access token the proxy mints from the user's Google credentials. The agent runs Claude Code in Vertex gateway mode and never holds a Google credential |
| GitHub API | `GET` and `HEAD` only | The user's GitHub token, only on the repository of the run. Other repositories are read anonymously |
| GitHub git | Read-only fetch of the repository of the run, and of what the plugin declares | None |
| Anything else | Refused, unless the plugin declares it and the user accepts it before the run | None |

Every header the agent sends is dropped unless it is on the proxy's list for that destination, so a plugin cannot slip a credential of its own next to the placeholder. The Files API, which could store data for later retrieval, is refused. Every request is logged with its decision.

The rules are written for each run by `internal/proxy`, from the repository of the run and the kind of Claude credential, and nothing else. Two tests pin them: `TestConfigRules` checks what the rules say, and `TestProxyRules` starts the real proxy image with them and probes it from the agent's network, against the real services, with fake credentials: every refusal must come from the proxy, and a fake credential must reach the service exactly where the rules add it.

Each run gets its own certificate authority, an ECDSA P-256 key valid for 24 hours that cannot sign another authority. Only the agent trusts it.

The proxy's credentials reach it in an environment file with exactly two variables. iron-proxy reads variables starting with `IRON_` as overrides of its configuration, so no other name ever reaches it. Its management API and its explicit tunnel listener stay off.

The proxy's limits are raised for agent traffic: request bodies up to 64 MiB, since the default truncates large conversations silently, and ten minutes for an upstream answer to begin. Its metrics listener is bound to its own loopback, out of the agent's reach.

## Credentials

The credentials live on the host and in the proxy container, never in the agent container.

| Credential | Source | Scope in the run |
|---|---|---|
| Claude subscription | A token from `claude setup-token` | Model requests only |
| Anthropic API key | The user's key | Model requests only |
| Google Vertex AI | The user's Application Default Credentials, including a `gcloud auth application-default login`, mounted read-only into the proxy | Model requests to one project and region |
| GitHub, during the run | The user's `gh` login | Reads on the repository of the run |
| GitHub, after the run | The user's `gh` login, used by the launcher on the host | The push and the pull request, after the user's yes |

## Push and pull request after review

The plugin never pushes. In the agent container, `git push` and `gh pr create` are stand-ins: they record the branch and the pull request's title, body, base branch and draft flag in the output directory, and ignore any repository, head, reviewer or label the agent passes, and tell the agent that both happen after the user's review. `gh pr view`, `list` and `status` answer that the pull request does not exist yet.

When the session ends, the launcher treats the output directory as untrusted input:

- the patch is refused if it touches anything under a `.git` directory;
- the branch name must pass `git check-ref-format`, or a generated name is used;
- the target repository is always the one the user asked for, never one written by the container;
- the patch is applied with `git am` to the host clone, which the container only ever had read-only, so no git configuration or hook from the run is ever used on the host, and the commits are signed by the user's own git configuration.

The launcher then shows the commits, the changed files, the pull request's title and body, and on request the full diff. On the user's yes, it pushes the branch, to the user's fork when they cannot push to the repository, and opens the pull request with `gh`.

## What a plugin declares

A plugin can need more than the defaults, such as a host it calls or a permission it needs on GitHub. It declares these in a Sealroom file in its repository, and the launcher shows them to the user before the run. A declaration only adds allowed requests, never credentials: a host declared by the plugin is reached without any of the user's credentials.

## Platforms

Sealroom runs with rootless Podman or Docker, on Linux and on macOS, and CI runs the end-to-end tests with both Docker and rootless Podman on Linux. The containers' restrictions use only options both runtimes share: the agent's in-memory home and work directories are writable through their mode, since Podman's `--tmpfs` has no owner option, and the session works in a directory the agent creates, which git accepts as the agent's own.

On Linux, what the agent writes to the output directory belongs to the agent's user, or to one of the user's subordinate users with rootless Podman, so the user cannot remove it directly: it has to be removed through a container, which the launcher does not do yet. SELinux, enforcing on Fedora and RHEL, is not handled yet: its labels keep a container from reading files in the home directory until the mounts are relabeled.

## Status

A prototype proved the design end to end on a real plugin and repository, with a Claude subscription: the lock-down, the subscription token added by the proxy, the refusal of foreign credentials, the read-only GitHub access that let the plugin check a branch ruleset, the recorded push and pull request, and the review on the host with a signed commit.

Still to prove:

- **Anthropic API key**: only the proxy's handling was checked, with a fake key.
- **Google Vertex AI**: not tried yet. The proxy's support for Google credentials was read in its source, not run, and an organization's policy may refuse requests from outside its own network.
- The push to a fork and the pull request creation.
- Copy and paste from the session in common terminals.
- SELinux, on Fedora and RHEL.
