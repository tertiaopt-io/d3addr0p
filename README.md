# DEAD DROP

Self-hosted, end-to-end encrypted, ephemeral messenger with the manners of a 1998 buddy list.
A [tertiaopt.io](https://tertiaopt.io) project. Live at [d3addr0p.com](https://d3addr0p.com).

Primary users are dissidents and reporters in hostile regimes, and their safety is the top
design constraint. Read the [threat model](docs/threat-model.md) and the
[honest limits](docs/honest-limits.md) before trusting anything here.

> This project does not claim "perfect secrecy." It commits to the property set P1–P7 in the
> [threat model](docs/threat-model.md), each with its honest limit. False confidence is the
> failure mode that gets people hurt. It is young and has had **no independent audit**; if you
> need the safest widely trusted messenger, use Signal.

## What it is

- **MLS group encryption** (RFC 9420 via OpenMLS, Rust compiled to wasm, running in the
  browser). Every conversation is an MLS group; all of one account's devices are members, so
  every device receives simultaneously.
- **No phone number, no email.** An account is a username plus an Argon2id-hardened passphrase.
  There is no recovery: lose the passphrase and the account is cryptographically gone.
- **Per-message lifetimes.** Each message carries its own: burn-on-read, a timer, or
  until-revoked, where revoking crypto-erases the stored copy on every device in the group.
- **A server the operator owns.** One static Go gateway that only ever relays opaque padded
  ciphertext, plus a small PHP control plane for accounts. The server cannot read messages
  because it never has the keys.
- **Desktop, deliberately.** An installable PWA and an Electron shell. There is no mobile
  client on purpose: presence is something you declare by sitting down, and signing off is
  supposed to mean something. The whole client wears an AIM-era skin — buddy list, away
  messages, warn-free.

## Layout

```
schema/         shared protobuf wire types + codegen (single source of truth)
control-plane/  typed PHP account API (strict_types, PHPStan/Psalm max). Never touches message bytes.
gateway/        Go realtime gateway + in-process bus. Carries opaque ciphertext only.
crypto/         OpenMLS (RFC 9420) client crypto core, Rust -> wasm. Runs in the browser.
client/         PWA client (consumes the wasm crypto core) + the AIM-style UI. Strict TS gate.
desktop/        Electron shell wrapping the deployed web app (mac + windows builds).
docs/           threat model, honest limits, architecture, decision log
```

The deployment scripts and the vhost for the reference instance are not part of this
repository; they describe one operator's live footprint. The pieces you need to run your own
instance are all here: the gateway is a dependency-free static Go binary, the control plane is
plain PHP behind any `/api` proxy, and the web root is static files with an
integrity-pinning service worker baked at build time.

## Build

```sh
make check          # schema lint + gateway vet/test/build + PHP phpstan/psalm + client typecheck/lint
make gen            # regenerate typed wire bindings for every tier
```

Per-tier toolchains: `buf` (schema), Go 1.22 (gateway), PHP 8.2 + Composer (control plane),
Node 20 (client), Rust + `wasm-pack` (crypto). Every gate is build-breaking.

Desktop builds, from `desktop/`: `npm run icons` once, then `npm run dist:mac:zip` and
`npx electron-builder --win zip --x64`. Prebuilt unsigned zips are on the
[releases page](https://github.com/tertiaopt-io/d3addr0p/releases).

## Design history

The decision log ([docs/decisions.md](docs/decisions.md)) records every architecture gate,
adversarial review, and accepted residual risk since M0, including the ones that constrain the
present: trust-on-first-use key exchange with no out-of-band verification yet (ADR-009), no
post-quantum claim while the OpenMLS provider lacks the KEM (ADR-007), and the padding,
sealed-mailbox, and revocation designs.

## Invariant

Payloads are end-to-end ciphertext. The gateway and the bus only ever carry opaque blobs and
never hold keys. The server cannot read messages because it never has the keys.

## License

[AGPL-3.0-or-later](LICENSE).
