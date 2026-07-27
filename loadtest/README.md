# loadtest

Harness for the Gate 8 performance targets (§4.6), built out at M6. Targets are not yet set
(Gate 8 deferred). Under ADR-005 (single node) the goal is vertical headroom plus the
rotating-front hop, not horizontal scale-out.

Planned: a k6 (or custom Go) harness measuring concurrent WebSocket sessions, messages/sec,
and p99 end-to-end latency, recorded with traffic shaping enabled. Placeholder only at M0.
