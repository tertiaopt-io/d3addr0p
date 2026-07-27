# Two-device test: status and procedure

This describes how to stand up the full stack for a real cross-device test, and states honestly
what works end-to-end today versus what is still pending. It is a developer document, not
app-facing copy.

## What is proven today

The cross-device path is built and tested at every layer, each verifiable on its own:

| Layer | Proof | Status |
| --- | --- | --- |
| MLS crypto roundtrip (offer → welcome → join → encrypt → decrypt) | `crypto/` cargo tests (`conversation.rs`) | passing, native |
| Gateway carries the whole two-client flow (offer → accept+welcome → ciphertext → receipt → ack), ciphertext-only | `gateway/internal/ws` `TestFullHandshakeAndMessage` | passing, real WebSockets |
| Client orchestration (gated mutual-accept handshake, transport envelope shapes, at-rest persistence, revoke, expiry) | `client/src/e2e.test.ts` | passing, two in-process Sessions |
| Live channel orchestration (contact → offer → accept → message, push events) | `client/src/live.test.ts` (fake gateway) | passing, deterministic |
| Owning Web Worker (sole writer): unlock → Argon2id → MSK wrap → IndexedDB, off the main thread | browser-verified via the launch preview | passing, real browser |
| **Full live path: real wasm handshake + protobuf + WebSocket through the real gateway** | two in-page sessions vs the running gateway (launch preview) | **passing, real browser** |

In the last row, two independent live sessions in one browser page connected to the running Go
gateway over real WebSockets, completed the real-wasm handshake (`createAndAdd` → Welcome →
`joinFromWelcome`), both reached `secure`, and a real MLS-encrypted message decrypted correctly on
the receiver. The app's owning Web Worker also connects to the gateway on mount (the menu bar shows
`◐ CONNECTED`) and renders a valid contact string on the new-channel screen, so the full
worker → controller → live → gateway → UI wiring is exercised.

## M4 wiring (done)

The controller is now wired to the live gateway transport:

- `client/src/live.ts` (`LiveChannel`) holds the WebSocket `Transport`, the per-conversation
  `Session` + wasm `Conversation`, and turns inbound frames into push events. It is injected with
  its browser-only dependencies (the `connect`, the `Conversation` factory, the `pushEvent` sink),
  so it stays gate-clean; the worker (`client/worker.js`) supplies those dependencies.
- The contact step is trust-on-first-use (ADR-009): each device advertises a copy-pasteable string
  `deaddrop:1:<routingKeyHex>:<sigKeyHex>`; the initiator pastes the peer's, offers, and the peer
  accepts. See ADR-017 for the bootstrap-routing design and its honest sealed-sender caveat (during
  the handshake the gateway can see which identity key is being contacted; steady-state routing keys
  are epoch-rotated and opaque).
- Protobuf wire glue is bundled once into `dist/wsadapter.bundle.js` (esbuild); the app modules stay
  raw ES modules.

Live messages are persisted to the crypto-erasable keyvault and survive a reload (ADR-018). A
received message holds without starting its destruction countdown until the recipient opens the
conversation (hold-until-seen), and the client connects/subscribes on unlock so the gateway hands
over anything it held while the recipient was offline.

A device's IDENTITY is now persistent (ADR-019): the signer is sealed under the MSK and restored on
login, so a contact string and bootstrap mailbox are STABLE across logins (browser-verified). This
persists only the signer, so it adds no forward-secrecy residual.

Honest limit: full conversation RESUME and durable cross-login message retrieval (reconstructing a
conversation's epoch mailbox after a reload to pull messages held for days) are NOT yet delivered.
That needs persisted group state, which activates the ADR-015 forward-secrecy residual and, in the
current model, the Rust-core separation of the long-lived signer from per-conversation groups. It is
a gated next step (ADR-019). Live messaging requires the owning worker; the main-thread fallback
rejects the live ops with a clear message.

## Local dev procedure (DEV ONLY, no TLS)

```sh
DD_ALLOWED_ORIGINS='*' infra/dev-stack.sh
```

This builds the wasm crypto, the client, and the gateway, then runs the gateway and a static file
server bound to the LAN so a second device can reach them. It prints the URLs. Open the client URL
on two devices on the same network, then on device A choose New channel, copy device B's contact,
paste it on A and Continue; accept on B; send a message.

`DD_ALLOWED_ORIGINS='*'` is needed for cross-port dev because the client (`:8087`) and the gateway
(`:8443`) are different origins, so the gateway's same-origin WebSocket check would otherwise reject
the connection. **This is for local testing only.** In production the app and `/ws` share one origin
behind Apache, so the default same-origin check passes and no override is set.

The script binds the gateway to `0.0.0.0` so a phone can reach it directly. **This is for local
testing only.** Production keeps the gateway on loopback behind Apache.

## Production path

Production fronts the loopback gateway with Apache `mod_proxy_wstunnel` inside the single Virtualmin
vhost, with real TLS so the client connects over WSS:

- gateway: `infra/run-gateway.sh` (runs as the unprivileged vhost user, binds `127.0.0.1:8443`,
  writes nothing to disk; see `docs/deployment-privileges.md`);
- Apache: `infra/apache/deaddrop.conf` (`/ws` → `ws://127.0.0.1:8443/`, plus the control-plane API
  and, at M3, the cover site at `/`).

Nothing in this stack requires root to run; root is needed only to install it.
