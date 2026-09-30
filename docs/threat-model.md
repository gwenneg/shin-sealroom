# Threat model

## What Sealroom protects

1. **The user's machine**: its files, keys, and every credential on it.
2. **The user's credentials used by the run**: the Claude or Vertex credential and the GitHub login, which the plugin must not be able to read, copy or use beyond what the run needs.
3. **The user's data**: the repository and anything else the plugin can read, which must not leave except through the channels the user sees and accepts.

## The adversary

A plugin or skill author who wants to steal credentials or data, or to change code the user will ship. They know Sealroom exists and can read its source. Their code runs as the agent does: hooks, MCP servers, scripts, and the instructions the model follows.

## What Sealroom trusts

| Trusted | Why it is acceptable |
|---|---|
| The container runtime and the kernel | Every container rests on them. Sealroom narrows what the agent container can do |
| The proxy | Built from a verified commit of an open source project, pinned by digest, and configured by Sealroom for each run |
| Claude Code | The agent itself. Sealroom contains what the plugin can do through it, not Claude Code's own behaviour |
| The model provider and GitHub | The destinations the user already uses |
| The Sealroom launcher | Built reproducibly and released with signatures and provenance |

## What Sealroom does not trust

Everything that comes from the plugin, and everything the agent container writes: the patch, the branch name, the recorded pull request, and every request that reaches the proxy.

## Attacks and defences

| Attack | Defence |
|---|---|
| Read the user's files or keys | Nothing from the host is mounted except the plugin and the repository, both read-only, and one output directory |
| Steal a credential | No credential exists in the agent container, only placeholders. The proxy adds the real ones |
| Find a credential on disk after the run | The file that hands the credentials to the proxy is deleted as soon as the proxy is created. The Claude credential is kept in the operating system's keychain, and handed to the keychain tools on their standard input, never in their arguments |
| Send data to a host of the attacker's | The agent container has no route out. The proxy refuses every host that is not allowed |
| Send data through an allowed host with the attacker's own credential | The proxy drops every header that is not on its list, requires the placeholder on the model API, and adds the user's GitHub token only on the repository of the run |
| Store data on the provider for later retrieval | The Files API is refused. Only the model endpoints are allowed |
| Push the code, or other data, to a repository of the attacker's | GitHub writes are refused. The push happens on the host, after the user's review, to the repository the user named |
| Use the user's GitHub token beyond the run | It is added only to reads on the repository of the run |
| Reach the user's files through the plugin's own links | The plugin is copied into the run directory with its links kept as links, never followed, so a link reaches only a path inside the container |
| Read another container's files, or have another container read the run's | With Podman under SELinux, the run's files are labeled for their container alone, except the CA certificate, which holds no secret |
| Get the launcher to mount more than intended | Every host path is checked: absolute and clean, never the root, the home directory or one of its parents, and no character that changes the meaning of a mount option. The agent's mounts are pinned by a test |
| Receive a real credential through the environment | The agent receives only a fixed list of variables, and every credential variable must hold the placeholder, or the run does not start |
| Reconfigure the proxy | The rules are written by the launcher and mounted read-only. The proxy's environment holds only the two credential variables, never an `IRON_` override, and its management API is off |
| Change the network rules | No capabilities, no privilege to gain, and the rules live in the proxy, outside the agent container |
| Run code on the host through the output | Every path of the patch is listed before it is applied, and one under a `.git` directory, in any letter case, is refused. The patch is applied to the host's own clone, which the container had read-only. The branch name is validated. The target repository never comes from the container |
| Make the host read, show or post one of its own files | Every file of the output directory must be a regular file inside it: a link is refused, never followed |
| Rewrite what the user reviews with terminal escape sequences | Everything shown is sanitised: control characters and invisible or direction-changing characters are shown as escapes |
| Slip an option into the push or the pull request | Every value from the session reaches `gh` as one `--flag=value` argument, the push never forces, and the target repository and credential helper are the launcher's |
| Hide a harmful change in the pull request | Not prevented. The user reviews the diff before anything leaves |
| Escape the container | Non-root, no capabilities, `no-new-privileges`, read-only root, resource limits. A kernel exploit remains possible and is named as a limit |
| Exhaust the machine | Memory, CPU, process and time limits |
| Tamper with the proxy image or the launcher | Built from verified sources, pinned by digest, released with signatures |

## Limits

- **What the model sees can leave through the model.** A plugin can have the repository's content sent to the model. It reaches only the user's own account with their provider, as any use of Claude Code does.
- **The pull request is a channel out.** Whatever the plugin writes into the diff or the pull request's text becomes visible once pushed. The review before the push is the control, and a large diff is hard to review.
- **Harm within what is allowed.** A plugin can make a harmful change that the user approves, or spend the user's model quota.
- **The containers share a kernel.** They run on the host's kernel, or on the kernel of the virtual machine Docker and Podman use on macOS, so a kernel flaw can break out.
- **Reads without a token can carry data in their path.** Anonymous reads of public GitHub content are allowed, and their paths are chosen by the agent. Sealroom relies on GitHub not showing those reads to the owners of the content.
