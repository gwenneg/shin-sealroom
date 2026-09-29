# Sealroom

**Run an AI agent plugin or skill in a sealed room, and keep your machine and your credentials out of its reach.**

Sealroom runs Claude Code with a third-party plugin or skill inside a container on your machine. You use it interactively, as you would on your own machine, while the plugin has no way to reach your files, read your credentials, or send your data anywhere you did not agree to. When the session ends, Sealroom shows you what the plugin changed, and nothing is pushed until you say yes.

> [!WARNING]
> Sealroom is early and not released. The design and the threat model come first, on purpose: a tool that asks for your trust has to show its reasoning before its code.

## Why

A Claude Code plugin runs with your user privileges. Its hooks run as shell commands and its MCP servers as processes, outside Claude Code's sandbox and permission prompts. Claude Code's documentation says it plainly: a plugin can execute arbitrary code on your machine. Reading every file of a plugin before using it is the advice, and almost nobody does it.

Running Claude Code in a container is a common answer, but it usually leaves the credentials inside the container and the network open, or open to whole domains. A plugin can then take your Claude or GitHub token, or send your code through an allowed domain with a token of its own.

## How it works

- The plugin runs in a container with no route out except a proxy.
- The proxy holds your credentials and adds them only to the requests the run needs: the model, and reads on the repository you work on. It refuses everything else, including requests that carry the plugin's own credentials.
- The container never pushes. Sealroom shows you the changes and the pull request on your machine, and pushes with your own GitHub login on your yes.

It is designed for a Claude subscription, an Anthropic API key, or Claude on Google Vertex AI. So far, only a Claude subscription has been used in a real run.

## Documents

- [Design](docs/design.md): how Sealroom works and the decisions behind it.
- [Threat model](docs/threat-model.md): what Sealroom defends against, what it trusts, and its limits.
- [Development](docs/development.md): the layout and the commands to build and test.

## License

[Apache License 2.0](LICENSE)
