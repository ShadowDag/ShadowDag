#!/bin/bash
# Wait for a TCP port on 127.0.0.1 to accept connections.
#
# Used as the ExecStartPre of shadowdag-miner.service so the miner doesn't
# try to talk to the node's RPC before the node has bound the socket.
#
# We deliberately do NOT use curl here: quoting JSON bodies inside a
# systemd ExecStartPre= line is fragile, and curl -f will also fail on
# transient 4xx/5xx responses during node startup. A plain TCP-connect
# check via bash's built-in /dev/tcp is both simpler and more reliable.
#
# Usage: wait-for-rpc.sh <port> [timeout_seconds]
set -u

PORT="${1:-19332}"
TIMEOUT="${2:-90}"

for i in $(seq 1 "$TIMEOUT"); do
    if (: </dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
        exit 0
    fi
    sleep 1
done

echo "wait-for-rpc: timed out after ${TIMEOUT}s waiting for 127.0.0.1:${PORT}" >&2
exit 1
