# The agent: Claude Code, git and the GitHub CLI, with stand-ins for the
# commands that would publish anything. It holds no credential; the proxy
# adds them. Every download is pinned and checked against a checksum.
FROM docker.io/library/debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

# Claude Code, the stable channel. Checksums from the release's manifest.json.
ARG CLAUDE_CODE_VERSION=2.1.280
ARG CLAUDE_CODE_SHA256_AMD64=1e08503dbdf3c2cb0d706d32f3408277388d1c76ef108673e8fe42c1b322925b
ARG CLAUDE_CODE_SHA256_ARM64=92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2
# The GitHub CLI. Checksums from the release's checksums file.
ARG GH_VERSION=2.101.0
ARG GH_SHA256_AMD64=9bca2d1c16825f109907a23307628a2f0698fbf99662b73a5cf0b020293072b8
ARG GH_SHA256_ARM64=b57e8063f18862647c9d22727c32e9da1b963f8bf9db648fe123a6975695640f

RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*

# The architecture comes from the image, so the build works without BuildKit.
RUN set -eu; \
    arch=$(dpkg --print-architecture); \
    case "$arch" in \
      amd64) platform=linux-x64; claude_sha=$CLAUDE_CODE_SHA256_AMD64; gh_sha=$GH_SHA256_AMD64 ;; \
      arm64) platform=linux-arm64; claude_sha=$CLAUDE_CODE_SHA256_ARM64; gh_sha=$GH_SHA256_ARM64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/lib/claude "https://downloads.claude.ai/claude-code-releases/$CLAUDE_CODE_VERSION/$platform/claude"; \
    echo "$claude_sha  /usr/local/lib/claude" | sha256sum -c -; \
    install -m 755 /usr/local/lib/claude /usr/bin/claude && rm /usr/local/lib/claude; \
    curl -fsSL -o /tmp/gh.tar.gz "https://github.com/cli/cli/releases/download/v$GH_VERSION/gh_${GH_VERSION}_linux_$arch.tar.gz"; \
    echo "$gh_sha  /tmp/gh.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gh.tar.gz -C /tmp; \
    install -m 755 "/tmp/gh_${GH_VERSION}_linux_$arch/bin/gh" /usr/bin/gh; \
    rm -rf /tmp/gh.tar.gz "/tmp/gh_${GH_VERSION}_linux_$arch"

# The stand-ins come first on PATH, ahead of the real git and gh in /usr/bin.
COPY bin/git bin/gh bin/sealroom-session /usr/local/bin/
RUN chmod 755 /usr/local/bin/git /usr/local/bin/gh /usr/local/bin/sealroom-session \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /home/agent agent

ENV HOME=/home/agent \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sealroom-session"]
