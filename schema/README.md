# schema

`deaddrop.proto` is the single source of truth for every type that crosses the
gateway/bus boundary (brief §6). Generate typed bindings for all tiers:

```sh
buf lint            # build-breaking in CI
buf generate        # writes Go -> gateway, TS -> client, PHP -> control-plane
```

Codegen outputs are committed and lint/typecheck-gated per tier. Do not hand-edit generated
files. The hard invariant: nothing in this schema may carry plaintext content or a sender
identity (§4.1). `payload` is opaque E2E ciphertext.

Requires `buf` (https://buf.build) on PATH.
