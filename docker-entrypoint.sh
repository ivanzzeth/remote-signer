#!/bin/sh
# Container entrypoint. Handles the bind-mount-ownership / drop-privileges
# dance so a bare `docker compose up` works for new users without manual
# chown gymnastics on the host.
#
# Flow when the container starts as root (the default — Dockerfile no
# longer ends with `USER signer`):
#
#   1. Read HOST_UID / HOST_GID from env (default: 1000:1000). These
#      identify the host user whose files the bind-mount maps into the
#      container; the container's process needs to match so writes show
#      up as that user on the host filesystem.
#
#   2. If REMOTE_SIGNER_HOME is set (the local compose passes the host
#      $HOME/.remote-signer path verbatim), ensure that directory
#      exists and is owned by HOST_UID. This fixes the new-user case:
#      docker auto-created the bind target as root because the host
#      didn't have the dir yet. Without this step the daemon hits
#      "permission denied" on the very first config write.
#
#   3. Drop privileges to HOST_UID:HOST_GID via gosu and exec the
#      daemon. gosu is preferable to su / sudo here because it doesn't
#      fork or signal-proxy — the daemon stays PID 1.
#
# Flow when the container starts as a non-root user (compose / docker
# run with explicit `--user`): skip the whole privilege dance and just
# exec the command. This preserves the prod compose's existing
# `read_only: true` + dropped-capabilities posture, which would refuse
# the chown / gosu paths above anyway.
#
# Compatibility: kept POSIX-sh (no bashisms) so the entrypoint can run
# on busybox / alpine images if the Dockerfile is ever rebased.

set -e

# Quick exit: container started as a non-root user. Skip the chown /
# gosu setup entirely — whoever orchestrated us already pinned the
# uid and they likely also chown'd the bind mount beforehand. This
# branch keeps the prod compose (USER signer pinned, read-only fs)
# fully working.
if [ "$(id -u)" != "0" ]; then
    exec "$@"
fi

TARGET_UID="${HOST_UID:-1000}"
TARGET_GID="${HOST_GID:-1000}"

# Ensure the bind-mount target exists and is owned by the target uid.
# Docker auto-creates missing bind sources as root:root; this step is
# the one that takes a "first-run from clean machine" install from
# permission-denied to functional. `chown` (without -R) is intentional —
# we only fix the mount-point itself, not arbitrary content inside.
# Files the daemon writes from this point on inherit ownership from
# its dropped-uid identity, which is what we want.
#
# We deliberately do NOT suppress errors here. Earlier versions did
# `|| true` and the suppression masked userns-remap / read-only-mount
# failures — the chown would silently fail, gosu would drop privileges,
# and the daemon would loop on "permission denied" with no clue why.
# A loud abort here gives operators a clear signal to investigate
# (manual chown, daemon config check, etc.).
if [ -n "${REMOTE_SIGNER_HOME}" ]; then
    echo "[entrypoint] ensuring ${REMOTE_SIGNER_HOME} is owned by ${TARGET_UID}:${TARGET_GID}" >&2
    mkdir -p "${REMOTE_SIGNER_HOME}"
    if ! chown "${TARGET_UID}:${TARGET_GID}" "${REMOTE_SIGNER_HOME}"; then
        echo "[entrypoint] FATAL: chown ${REMOTE_SIGNER_HOME} → ${TARGET_UID}:${TARGET_GID} failed." >&2
        echo "[entrypoint]   Likely causes:" >&2
        echo "[entrypoint]     - docker daemon has userns-remap configured;" >&2
        echo "[entrypoint]       remap maps container-root to a host uid that doesn't" >&2
        echo "[entrypoint]       have CAP_CHOWN on the bind-mount target." >&2
        echo "[entrypoint]     - bind mount source is on a filesystem that refuses chown" >&2
        echo "[entrypoint]       (NFS without root_squash, certain FUSE mounts)." >&2
        echo "[entrypoint]   Workaround: run \`sudo chown -R \$(id -u):\$(id -g) ${REMOTE_SIGNER_HOME}\`" >&2
        echo "[entrypoint]               on the host before \`docker compose up\`." >&2
        exit 1
    fi
fi

# Drop to the target uid and exec the daemon. gosu is signal-transparent
# (daemon stays PID 1, SIGTERM from `docker stop` reaches it directly).
exec gosu "${TARGET_UID}:${TARGET_GID}" "$@"
