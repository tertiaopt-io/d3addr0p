# Deployment & privilege model

Requirement (owner): the application is installed as root, but **everything needed to run it
runs unprivileged inside a Virtualmin vhost**, so a compromise of any component cannot reach
other data on the server. This document audits each component, states what needs root **only at
install time**, and gives the acceptance checks. Verified empirically where noted.

## Principle

- **Install-time (root, once):** copy binaries, drop the systemd unit (or the cron entry), enable
  the Apache modules, install PHP/Composer. Nothing the app *runs* needs these privileges.
- **Run-time (unprivileged):** every running process is the vhost user (or a transient
  `DynamicUser`), binds only high loopback ports, writes nothing outside its own sandbox, and is
  isolated from other vhosts by Unix permissions.

## Per-component audit

| Component | Runs as | Port | Writes to disk? | Needs root at runtime? |
|-----------|---------|------|-----------------|------------------------|
| Go gateway | vhost user / systemd `DynamicUser` | `127.0.0.1:8443` (high, loopback) | No (in-memory bus, logs to journal/stderr) | **No** |
| In-process bus | inside the gateway process | n/a | No (memory only, TTL) | **No** |
| PHP control plane | vhost user (PHP-FPM pool) | via FPM socket, fronted by Apache | No message data (§5.10) | **No** |
| Client (PWA) | the user's browser | n/a (static assets) | n/a | **No** |
| Crypto core (WASM) | the user's browser | n/a (build artifact) | n/a | **No** |
| Apache edge | root-managed service | 443 (root-bound by Apache itself) | scrubbed logs (§5.10) | install/config only |

Key facts that make this hold:
- **Static binary.** The gateway is built `CGO_ENABLED=0` → a statically-linked ELF with **no
  libc or shared-library dependency**, so it runs in a minimal vhost with nothing installed.
  Verified: `file` reports "statically linked".
- **High loopback port only.** The gateway binds `127.0.0.1:8443` (> 1024), which needs no
  privilege. Apache (already root) reverse-proxies `:443` → the loopback gateway via
  `mod_proxy_wstunnel`; the app never binds a privileged port. Verified: ran as uid 501,
  `/healthz` returned 200.
- **No disk writes.** The bus is in-memory with a TTL; the gateway logs only to stderr/journal;
  the control plane never receives message bytes. So no privileged paths are touched and the
  process works under a read-only root filesystem sandbox.
- **Vhost isolation.** Virtualmin runs each vhost's PHP-FPM pool as that vhost's Unix user, and
  the gateway's systemd unit uses `DynamicUser` + `ProtectHome` + `ProtectSystem=strict`, so
  neither can read another vhost's files.
- **Future database.** When account/config storage is added, it uses the vhost's provisioned DB
  user (Virtualmin per-vhost DB), never the root DB account.

## Two supported run models

1. **systemd service (operator has root on the box, ADR-001).** [systemd unit](../infra/systemd/deaddrop-gateway.service)
   runs the gateway as a transient unprivileged `DynamicUser` with a hardened sandbox (no
   capabilities, no device access, loopback-only). Installing the unit needs root once; the
   process runs unprivileged.
2. **Pure vhost (no per-app systemd).** [run-gateway.sh](../infra/run-gateway.sh) runs the
   gateway as the vhost user; keep it alive with the user's own `cron @reboot` (example in the
   script). No root, no system service.

## Acceptance checks

- [x] Gateway is a static binary with no dynamic dependencies (`file` → statically linked).
- [x] Gateway runs as a non-root user (uid != 0) on a high loopback port and serves `/healthz`.
- [x] Gateway writes nothing to disk at runtime (in-memory bus; logs to journal/stderr).
- [ ] On the deploy host: confirm the systemd unit starts under `DynamicUser` and that
      `systemd-analyze security deaddrop-gateway` reports a hardened score.
- [ ] On the deploy host: confirm PHP-FPM runs the control plane as the vhost user, not root.
- [ ] Confirm Apache proxies `:443` → `127.0.0.1:8443` and the app user owns no privileged port.
