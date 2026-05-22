#!/bin/sh
# Local Linux smoke test for the docker-compose.local.yml flow.
#
# Reason this exists: the Docker setup is sensitive to Linux-specific
# behaviour (bind-mount ownership, kernel user namespaces, gosu cap
# requirements) that macOS Docker Desktop masks. A workflow that "works
# on my mac" can absolutely fail on a real Ubuntu host. Running the
# smoke inside a real Linux VM catches those regressions before the
# release workflow ships a broken image to ghcr.
#
# Requires OrbStack (the project's recommended local VM runner —
# brew install orbstack). Adjust the `orb` invocations for lima /
# multipass / vagrant if you prefer those.
#
# Run from repo root:
#   make docker-smoke    # if you've added a Makefile target
#   sh scripts/docker-smoke-linux.sh

set -e

MACHINE="${ORB_MACHINE:-docker-smoke}"
DISTRO="${ORB_DISTRO:-ubuntu:noble}"

# Lazy provision: create the VM only if it doesn't exist. Subsequent
# runs reuse the same VM (docker cache, apt cache, etc.) so iteration
# is fast.
if ! orbctl list 2>/dev/null | grep -q "^${MACHINE}\s"; then
    echo "[smoke] creating ${DISTRO} VM '${MACHINE}'"
    orbctl create "${DISTRO}" "${MACHINE}"
fi

# Install docker-ce inside the VM (idempotent — re-runs are no-ops).
echo "[smoke] ensuring docker-ce is installed in VM"
orb -m "${MACHINE}" bash -c '
    set -e
    if ! command -v docker >/dev/null 2>&1; then
        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
            | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
        sudo usermod -aG docker $USER
    fi
'

# Ship the current working tree (including any uncommitted edits) into
# the VM. OrbStack mounts the macOS root at /mnt/mac inside the VM, so
# we can just cp from there — no rsync-over-ssh ceremony, and the cp
# happens inside the VM so it works regardless of OrbStack's exposed
# filesystem semantics.
REPO_ABS="$(pwd)"
MAC_PATH_IN_VM="/mnt/mac${REPO_ABS}"
echo "[smoke] copying ${REPO_ABS} → VM:~/work/remote-signer"
orb -m "${MACHINE}" bash -c "
    rm -rf ~/work/remote-signer
    mkdir -p ~/work
    cp -a '${MAC_PATH_IN_VM}' ~/work/remote-signer
    # Drop heavy dirs that aren't needed for the smoke and slow the
    # docker build context send. internal/web/dist gets re-built by
    # the Dockerfile's webbuilder stage anyway.
    rm -rf ~/work/remote-signer/node_modules \
           ~/work/remote-signer/internal/web/dist \
           ~/work/remote-signer/test-results \
           ~/work/remote-signer/playwright-report
"

# Run the local compose. The VM's UID happens to match the macOS user's
# (OrbStack auto-maps), so HOST_UID/HOST_GID resolve correctly.
echo "[smoke] starting daemon via docker-compose.local.yml"
orb -m "${MACHINE}" bash -c '
    set -e
    cd ~/work/remote-signer
    rm -rf ~/.remote-signer  # always start clean
    sg docker -c "docker compose -f docker-compose.local.yml build"
    sg docker -c "HOST_UID=\$(id -u) HOST_GID=\$(id -g) docker compose -f docker-compose.local.yml up -d"

    # Wait for /health to come up. Soft-start mode means /health
    # answers even without admin, so this is the clean readiness probe.
    for i in $(seq 1 30); do
        if sg docker -c "docker exec remote-signer-local wget -qO /dev/null http://127.0.0.1:8548/health"; then
            echo "[smoke] PASS — /health 200 on first try set"
            sg docker -c "docker compose -f docker-compose.local.yml down"
            exit 0
        fi
        sleep 1
    done

    echo "[smoke] FAIL — daemon never became healthy. Container logs:"
    sg docker -c "docker compose -f docker-compose.local.yml logs --tail 50"
    sg docker -c "docker compose -f docker-compose.local.yml down"
    exit 1
'
