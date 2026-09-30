# A hostile stand-in for Claude Code, for TestHostile. It derives from the
# real agent image, exactly as a plugin's code runs: as the agent's user,
# inside the sealed container. The script tries every way out it can and
# writes one result line per attempt into the repository, so the results come
# back to the host in the session's patch, where the test asserts each one.
ARG AGENT_IMAGE
FROM ${AGENT_IMAGE}
COPY claude /usr/local/sbin/claude
