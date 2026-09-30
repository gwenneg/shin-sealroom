# Design

This document describes how Sealroom works and why. Every decision below is judged by one question: does it make Sealroom easier to trust?

It describes the whole design, including parts not built yet. The [status](#status) at the end says which. The [threat model](threat-model.md) says what the design defends against and where it stops.

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
| **Agent container** | Container runtime | Claude Code, a copy of the plugin mounted read-only, a copy of the repository, and stand-ins for `git push` and `gh pr create` |
| **Proxy container** | Container runtime | The only route out of the agent: allows each request by host, method and path, holds the credentials and adds them to allowed requests, refuses everything else |

The launcher drives Podman or Docker directly, Podman first when both are installed. It does not depend on Compose, whose command and behaviour differ between Docker's plugin, the standalone binary and Podman.

## The run directory

Each run gets a directory under the user's cache directory (`~/.cache/sealroom/runs` on Linux, `~/Library/Caches/sealroom/runs` on macOS). It is under the home directory, so a runtime in a virtual machine that shares only the home directory, as on macOS, can mount it. Only the user can enter it. It holds the copy of the plugin, the clone, the proxy's rules, the run's CA and the proxy's credentials file, and the output directory. The files the proxy reads are readable by all, since the proxy runs as its own user, but the directory around them is the user's alone. The credentials file is readable by the user only: the runtime's command line reads it on the proxy's behalf. The output directory is writable by the agent's user.

The launcher creates the internal network on a random private subnet, starts the proxy and waits until it listens, then attaches the agent to the user's terminal. Ctrl-C belongs to the session while it runs. When the session ends, however it ends, the launcher removes the proxy and both networks.

## The agent container

| Restriction | Why |
|---|---|
| Internal network only: no gateway, and DNS answered by the proxy | Nothing reaches the internet except through the proxy. Raw sockets, hard-coded addresses and DNS tunnels have no route |
| Non-root user, all capabilities dropped, `no-new-privileges` | No privilege to gain, and nothing that could change the network rules |
| Read-only root filesystem, throwaway home and work directory in memory | The plugin cannot alter the tooling, and nothing persists after the run |
| Nothing from the host mounted, except copies of the plugin and the repository read-only, the proxy's CA certificate, and one output directory, all in the run directory | No home directory, no keys, no credentials, no container runtime socket |
| No credential of any kind, only placeholders | A plugin that reads every file and every environment variable finds nothing usable |
| Memory, CPU, process and time limits | A plugin can use only a bounded share of the machine |

The proxy container is locked down the same way: read-only root, no capabilities, `no-new-privileges`, the same limits, and only its configuration, the CA certificate and key mounted, read-only. It answers DNS and HTTPS on low ports through the `ip_unprivileged_port_start` setting of its own network namespace, not a capability. Its credentials arrive in an environment file that only the proxy receives.

Both containers start with `--pull never`, so a run never reaches a registry. The restrictions are set in one place, `internal/sandbox`, and `TestArgsSeal` fails if one goes missing or a forbidden option appears, such as `--privileged`, an added capability, a host namespace, a published port, or an extra mount. A host path mounted into a container is refused if it is not absolute and clean, if it is the root, the home directory or one of its parents, or if it contains a character that would change the meaning of the mount option. The agent receives only a fixed list of environment variables, and every credential variable must hold the placeholder.

The image holds Claude Code, git and the GitHub CLI, each downloaded at a pinned version and checked against a checksum in the image's definition, on a Debian base pinned by digest. Claude Code follows its stable channel, with its auto-updater and non-essential traffic turned off, and its first-run screens skipped. The stand-ins for `git` and `gh` come first on the `PATH`, ahead of the real commands.

The plugin is copied into the run directory before the session, so the agent mounts Sealroom's copy, a snapshot of the plugin at start, and never the user's own directory. The copy keeps symbolic links as links without following them, so no file outside the plugin is copied through one; it skips git metadata, refuses anything but files, directories and links, and stops at 100,000 files or 1 GiB.

The repository is copied into the container at start, so the plugin never writes to the user's clone. The output directory receives the changes as a patch, the branch name, and the recorded pull request, and nothing else is written on the host. When Claude Code exits, the session script commits whatever is left uncommitted and writes every commit since the repository's default branch as one patch.

## The proxy

The proxy is [iron-proxy](https://github.com/paradigmxyz/iron-proxy), an egress firewall built for untrusted workloads. It intercepts TLS with a CA created for the run, so it sees each request's host, method, path and headers.

Sealroom does not use its published images or binaries, which are not signed. It builds the proxy from a release commit whose signature was verified when it was pinned, on a minimal base image pinned by digest, with Go modules checked against iron-proxy's `go.sum`. The image, in `images/proxy`, runs as a non-root user and holds nothing but the proxy's static binary.

### What each credential can do

| Destination | Allowed | Credential added by the proxy |
|---|---|---|
| Anthropic API | `POST` to the model endpoints, and Claude Code's read-only policy endpoints | The user's Claude credential, only in place of the agent's placeholder. A request without the placeholder is refused, so a plugin's own key never gets through |
| Google Vertex AI | `POST` to Anthropic's models in the user's project and region, and nothing else on Google | An access token the proxy mints from the user's Google credentials. The agent runs Claude Code with `CLAUDE_CODE_SKIP_VERTEX_AUTH` and never holds a Google credential |
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
| Claude subscription | A token from `claude setup-token`, saved with `sealroom login`, or `CLAUDE_CODE_OAUTH_TOKEN` | Model requests only |
| Anthropic API key | Saved with `sealroom login`, or `ANTHROPIC_API_KEY` | Model requests only |
| Google Vertex AI | The user's Application Default Credentials, including a `gcloud auth application-default login`, mounted read-only into the proxy | Model requests to one project and region |
| GitHub, during the run | The user's `gh` login | Reads on the repository of the run |
| GitHub, after the run | The user's `gh` login, used by the launcher on the host | The push and the pull request, after the user's yes |

With Vertex, set as for Claude Code itself (`CLAUDE_CODE_USE_VERTEX`, `ANTHROPIC_VERTEX_PROJECT_ID`, `CLOUD_ML_REGION`), the launcher copies the user's Application Default Credentials, a user login from `gcloud auth application-default login` or a service account key, into the run directory, and mounts the copy into the proxy only; the copy is deleted when the run ends, and the user's own file is never mounted, so SELinux relabeling never touches it. iron-proxy's `gcp_auth` mints short-lived access tokens from it and adds them only to requests for Anthropic's models in the user's project and region. Any other project, region or publisher is refused by the allowlist, so a request cannot reach a project of anyone else's, and headers such as `x-goog-user-project` or an API key of the agent's never reach Google. The Anthropic API is not reachable at all with Vertex.

`sealroom login` reads the Claude credential without showing it, and saves it in the operating system's keychain: the login Keychain on macOS, through `security`, and the Secret Service on Linux, such as GNOME Keyring or KWallet, through `secret-tool`. Both tools receive the secret on their standard input, never in their arguments, where any process on the machine could read it. Only one credential is saved: saving one kind removes the other, and `sealroom logout` removes it. A credential must look like a subscription token or an API key, with nothing but letters, digits, dashes and underscores, so none can carry a newline into a file or a space into a keychain command. The environment variables, when set, come first, for scripts.

For a run, the credentials are written to a file only the user can read, which the runtime's command line reads when it creates the proxy container. The launcher deletes the file as soon as the proxy is created, whatever the outcome, so no credential stays on disk.

## Push and pull request after review

The plugin never pushes. In the agent container, `git push` and `gh pr create` are stand-ins: they record the branch and the pull request's title, body, base branch and draft flag in the output directory, and ignore any repository, head, reviewer or label the agent passes, and tell the agent that both happen after the user's review. `gh pr view`, `list` and `status` answer that the pull request does not exist yet.

When the session ends, the launcher treats the output directory as untrusted input, read by `internal/review` only:

- every file must be a regular file inside the output directory, opened through Go's `os.Root` and checked again once open: a symbolic link the agent planted, to a key of the host's for example, is refused rather than followed, so it is never shown or posted;
- sizes are limited: 16 MiB for the patch, 64 KiB for the pull request's body, 256 bytes for a branch name, a title or a base branch;
- every path the patch touches is listed with `git apply --numstat` before anything is applied, and the patch is refused if one is under a `.git` directory, in any letter case, since a file written into `.git/hooks` would run on the host at the next git command;
- the branch name must pass `git check-ref-format` and must not start with a dash, or a generated name is used, as it is when the branch already exists;
- the target repository is always the one the user asked for, never one written by the container;
- the patch is applied with `git am` to the host clone, which the container only ever had read-only, so no git configuration or hook from the run is ever used on the host, and the commits are signed by the user's own git configuration.

Everything shown to the user is sanitised: control characters, escape sequences, and invisible or direction-changing characters are shown as escapes, so nothing from the session can hide a line or rewrite what the user reads. What is pushed is never altered: the user reviews it, escapes visible, and the same bytes are sent. The diff is shown with git's external diff tools and text conversion off.

The launcher then shows the commits, the changed files, the pull request's title, base and body, and on request the full diff, in a pager. It empties the output directory through a container running as the agent's user with no network, since on Linux what the agent wrote belongs to that user. Then it asks whether to push the branch and open the pull request. On no, nothing leaves, and the branch stays in the run's clone. On yes:

- the branch goes to the repository when the user can push to it, otherwise to the user's fork of the same name, which the launcher offers to create when it does not exist;
- the push never forces, and its only credential helper is the GitHub CLI's login, the user's own;
- the pull request is opened with `gh`, with the title, body, base and draft flag the session recorded, the same bytes the user reviewed. Without a recorded pull request, the last commit's message makes one, shown before the question like any other. A base that is not a branch of the repository gives way to its default branch;
- every value from the session reaches `gh` as a single `--flag=value` argument, so a title such as `--web` stays a title, and the base is escaped in the API path that checks it.

## What a plugin declares

A plugin can need more than the defaults, such as a host it calls or a permission it needs on GitHub. It declares these in a Sealroom file in its repository, and the launcher shows them to the user before the run. A declaration only adds allowed requests, never credentials: a host declared by the plugin is reached without any of the user's credentials.

## Platforms

Sealroom runs with rootless Podman or Docker, on Linux and on macOS, and CI runs the end-to-end tests with both Docker and rootless Podman on Linux. The containers' restrictions use only options both runtimes share: the agent's in-memory home and work directories are writable through their mode, since Podman's `--tmpfs` has no owner option, and the session works in a directory the agent creates, which git accepts as the agent's own.

On Linux, what the agent writes to the output directory belongs to the agent's user, or to one of the user's subordinate users with rootless Podman, so the user cannot remove it directly: the launcher empties it through a container after the review.

SELinux, enforcing on Fedora and RHEL, keeps a container from reading files in the home directory unless they carry a container label. With Podman, every mount gets one through Podman's `relabel` option: `private` for files one container reads, which ties them to that container so no other container on the machine can read them, and `shared` for the run's CA certificate, which the proxy and the agent both read. Relabeling changes the labels on the host, which is why only files of the run directory are ever mounted. Podman ignores the option where SELinux is off. Docker's `--mount` has no such option, and Docker confines containers with SELinux only when its daemon is set to. A container's SELinux separation is never turned off: `TestArgsSeal` refuses `label=disable`.

## Status

Built and tested in CI, with Docker and rootless Podman on Linux:

- the agent and proxy images, and every restriction of both containers;
- the proxy's rules for a run, probed against the real proxy and services;
- `sealroom run` from the session to the pull request, with a Claude subscription token or an Anthropic API key from the keychain or the environment, and the GitHub token from the GitHub CLI. The push and the pull request were also run for real on a test repository, with a signed commit.
- `sealroom login` and `logout`, with the macOS Keychain, checked by hand.
- both images, built for amd64 and arm64. Publishing them to GitHub's container registry, with a build provenance attestation, is ready but off until the maintainer turns it on.

A prototype also ran the whole design by hand on a real plugin and repository, with a Claude subscription, through the review on the host with a signed commit.

Not built yet:

- what a plugin declares;
- the launcher's use of the published images: it still uses images built locally.

Not tried yet:

- **Google Vertex AI with real credentials**: the rules are probed against the real proxy with fake credentials, which shows each request reaching the right step, but no real token has been minted, and an organization's policy may refuse requests from outside its own network.
- **An Anthropic API key in a real session**: only the proxy's handling was checked, with a fake key.
- The push to a fork, and creating the fork.
- Copy and paste from the session in common terminals.
- **The Secret Service on Linux**, for `sealroom login`: built, not run, since CI has no Secret Service.
- **SELinux with Podman, on Fedora and RHEL**: built, but only run where SELinux is off. The [development guide](development.md#checking-on-fedora) has the check to run on Fedora.
