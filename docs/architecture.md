# Architecture (single-vhost, M0 baseline)

Reduced from brief §4 and §8 per the ADR-005 decision: one node is the whole system. The
load-bearing invariant from §4.1 is unchanged and non-negotiable.

## Invariant

**Payloads are end-to-end ciphertext. The gateway and the in-process bus only ever carry
opaque blobs and never hold decryption keys.** This is what makes "encrypted even on the
bus" true by construction. The client does all cryptography.

## Topology

```
  [ Packaged client / web client ]      <- holds keys, does ALL crypto
            |  wss (TLS, common-stack fingerprint)
            v
  [ Apache vhost: mod_proxy_wstunnel ]   <- TLS termination (NO decoy site: the landing page
                                             describes the product openly, see threat-model P5)
            |  ws (loopback)
            v
  [ Go gateway (systemd, CGO_ENABLED=0) ]
            |  in-process Bus interface (NATS-style subjects)
            v
  [ In-process fan-out: per-recipient mailbox subjects, in-memory, TTL ]
            |
  [ Delivery back to subscribed recipient connections ]

  [ PHP-FPM control plane ]              <- account/identity/config APIs, no message content
```

Everything above runs on the one Virtualmin host. Disposable rotating fronts (M3, Gate 12)
sit in front of the Apache vhost so the burned artifact is never the operator's origin IP.

## Tiers

| Tier | Lang | Role | Sees plaintext? | Sees who-talks-to-whom? |
|------|------|------|-----------------|--------------------------|
| client | TS, hardened PWA | All crypto, key custody, lifetime enforcement | yes (it is the endpoint) | n/a |
| gateway | Go | WS termination, publish/subscribe opaque envelopes | **no** | **no** (sealed sender, M3) |
| bus | Go (in-process) | Route by opaque recipient mailbox, in-memory TTL | **no** | only an opaque routing key |
| control-plane | PHP | Account/config APIs, no message bytes | **no** | **no graph stored** |

## What crosses the bus

Exactly one shape: an `Envelope` (see [../schema/deaddrop.proto](../schema/deaddrop.proto)).
It carries a random `message_id`, an opaque `routing_key` (a per-recipient mailbox, not an
account identity), the E2E `payload` (ciphertext, padded to a fixed bucket by the client at
M3), and a `ttl_seconds`. There is **no sender field** (sealed sender). There are no stored
timestamps. The gateway cannot derive who sent a message or what it says.

## Logs-nothing posture (M0 stance, full checklist at M8)

- Gateway: no content or metadata to disk; metrics are aggregate counts/latencies only.
- Bus: in-memory, short TTL, no archival, no on-disk persistence.
- Control plane: no message bytes ever reach it; no routing pairs logged.
- Edge (Apache): access/error logs that capture IPs, endpoints, sizes, timing are scrubbed
  or disabled at M3/M8.
- OS: mlock sensitive memory, disable core dumps, disable/encrypt swap (M4/M8).

## Deferred-but-seamed

- **Externalize the bus:** replace the in-process `Bus` impl with a NATS/JetStream client.
  Call sites do not change.
- **Horizontal gateways:** the gateway is stateless w.r.t. message content; scaling out is a
  load-balancer + shared bus problem, deferred under ADR-005.
