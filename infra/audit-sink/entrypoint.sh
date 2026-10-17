#!/bin/sh
# Local S3-compatible WORM audit sink (VersityGW, POSIX backend with versioning + object lock).
# Starts the gateway, then creates two least-privilege users (idempotent):
#   shipper  - may only add objects (bucket policy set by scripts/audit_sink_setup.py)
#   auditor  - may only read objects, versions and retention
# All credentials are DUMMY values for the local demo.
set -eu
mkdir -p /data/objects /data/versions /data/iam
versitygw --port :7070 --health /health --quiet --iam-dir /data/iam \
    posix --versioning-dir /data/versions /data/objects &
pid=$!
trap 'kill -TERM "$pid"' TERM INT
until wget -q -O /dev/null http://127.0.0.1:7070/health; do sleep 0.5; done
admin() { versitygw admin -a "$ROOT_ACCESS_KEY" -s "$ROOT_SECRET_KEY" --er http://127.0.0.1:7070 "$@"; }
existing=$(admin list-users)
for pair in "$SINK_SHIPPER_ACCESS_KEY:$SINK_SHIPPER_SECRET_KEY" "$SINK_AUDITOR_ACCESS_KEY:$SINK_AUDITOR_SECRET_KEY"; do
    user=${pair%%:*}
    if ! printf '%s\n' "$existing" | grep -q "^$user "; then
        admin create-user -a "$user" -s "${pair#*:}" -r user
        echo "created sink user $user"
    fi
done
touch /tmp/users-ready
wait "$pid"
