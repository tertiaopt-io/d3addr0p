# skin preview

`transmit.html` is a durable, self-contained preview of the DEAD DROP transmit screen. It links
the **canonical** skin so it can never drift from the real tokens:

- `../src/skin/tokens.css` — the design tokens (the source of truth).
- `../src/skin/transmit.css` — the reusable skin layer (the `.dd` classes).

The small inline script just ticks the burn countdowns so you can watch a message crypto-erase to
a tombstone; it is preview-only and not part of the app.

## View it on a phone (same Wi-Fi as the host)

Serve the `client/` directory so the relative CSS links resolve, then open the page:

```sh
python3 -m http.server 8787 --bind 0.0.0.0 --directory client
# then on your phone (replace with the host's LAN IP):
#   http://<lan-ip>:8787/preview/transmit.html
```

This is a dev preview only; it exposes `client/` on the LAN. Stop the server when done.

## Status

This is M5 design exploration. The skin is captured here as reusable CSS; wiring it into the live
app (the conversation list, key-exchange/accept handshake, unlock, and the countdown as real
components driven by the M2 lifetime manager) is the next step.
