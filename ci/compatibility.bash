#!/usr/bin/env bash
set -euo pipefail

new_binary=$1
old_binary=$2
work_dir=$(mktemp -d)

cleanup() {
    if test -n "\${client_pid:-}"; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
    if test -n "\${server_pid:-}"; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    if test -n "\${echo_pid:-}"; then kill "$echo_pid" 2>/dev/null || true; wait "$echo_pid" 2>/dev/null || true; fi
    rm -rf "$work_dir"
}
trap cleanup EXIT

wait_for_port() {
    port=$1
    for _ in $(seq 1 100); do
        if (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

run_case() {
    server_binary=$1
    client_binary=$2
    label=$3
    case_dir=$work_dir/$label
    mkdir -p "$case_dir"

    python3 -u -c '
import socket
import sys
path = sys.argv[1]
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(4)
with open(path, "w") as port_file:
    port_file.write(str(listener.getsockname()[1]))
while True:
    connection, _ = listener.accept()
    with connection:
        while True:
            payload = connection.recv(65536)
            if not payload:
                break
            connection.sendall(payload)
' "$case_dir/service-port" >"$case_dir/echo.log" 2>&1 &
    echo_pid=$!
    for _ in $(seq 1 100); do
        test -s "$case_dir/service-port" && break
        sleep 0.1
    done
    local_port=$(cat "$case_dir/service-port")

    "$server_binary" server --bind-addr 127.0.0.1 --bind-tunnels 127.0.0.1 \
        --min-port 19000 --max-port 19000 --secret compatibility-secret \
        >"$case_dir/server.log" 2>&1 &
    server_pid=$!
    wait_for_port 7835

    "$client_binary" local "$local_port" --local-host 127.0.0.1 --to 127.0.0.1 \
        --port 19000 --secret compatibility-secret >"$case_dir/client.log" 2>&1 &
    client_pid=$!
    wait_for_port 19000

    python3 - 19000 <<'PY'
import socket
import sys
connection = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
connection.sendall(b"ltr-bore-compatibility")
assert connection.recv(64) == b"ltr-bore-compatibility"
connection.close()
PY

    kill "$client_pid" "$server_pid" "$echo_pid"
    wait "$client_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    wait "$echo_pid" 2>/dev/null || true
    client_pid=
    server_pid=
    echo_pid=
}

run_case "$new_binary" "$old_binary" new-server-old-client
run_case "$old_binary" "$new_binary" old-server-new-client
echo "Bore/LTR compatibility matrix passed"
