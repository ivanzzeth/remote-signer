# remote-signer desktop shell

Thin [Electron](https://www.electronjs.org/) wrapper around the
remote-signer daemon. Same React UI as the web frontend — the shell's
only jobs are:

1. Find (or spawn) a `remote-signer` daemon on `127.0.0.1:8548`.
2. Wait for `/health` to respond.
3. Open a `BrowserWindow` pointed at the daemon's HTTP root.

No IPC, no preload bridge, no custom protocol: the renderer talks to
the daemon the same way every other client does (signed Ed25519 HTTP).

## Run from source

```bash
# From the repo root — the Makefile orchestrates Go build + npm install.
make desktop-dev
```

This sequences:

1. `make web` → build the React bundle into `internal/web/dist/`.
2. `make build` → produce a `remote-signer` binary at the repo root.
3. `npm install` + `npm start` inside `electron/`.

The Electron main process searches for the binary in this order:

1. `$REMOTE_SIGNER_BIN` (manual override; handy when iterating only on
   the shell)
2. `<resourcesPath>/bin/remote-signer` (electron-builder extra-resource
   path; only populated in packaged builds)
3. `<repo-root>/remote-signer` (the path `make build` writes to)
4. `<repo-root>/dist/remote-signer` (CI artefact dir)

If none exist the app shows a native error dialog and exits — no
silent failure.

## Lifecycle

- If a daemon is already responding on 8548 when the shell starts, we
  **attach** instead of spawning. Quitting the desktop app leaves the
  external daemon alone.
- If the shell spawns the daemon itself, quitting (or closing the last
  window on non-macOS) kills it cleanly via SIGTERM.

## Package installers

```bash
make desktop-dist
```

Produces `electron/out/`:

- macOS: `Remote Signer-<ver>-arm64.dmg`, `Remote Signer-<ver>.dmg`
- Windows: `Remote Signer Setup <ver>.exe` (NSIS)
- Linux: `Remote Signer-<ver>.AppImage`

Code signing is **not** wired up out-of-the-box. To produce trusted
installers, set the standard electron-builder env vars before running
`make desktop-dist`:

- macOS: `CSC_LINK`, `CSC_KEY_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`,
  `APPLE_TEAM_ID` (for notarisation)
- Windows: `CSC_LINK`, `CSC_KEY_PASSWORD`

See [electron-builder docs](https://www.electron.build/code-signing) for the full matrix.

## Why no `nodeIntegration`?

The renderer only runs the React app — there is nothing in the
renderer that needs Node APIs. Keeping `nodeIntegration: false` and
`contextIsolation: true` matches Electron's secure defaults and keeps
the attack surface identical to running the web UI in a regular
browser.
