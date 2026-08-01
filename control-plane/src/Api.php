<?php

declare(strict_types=1);

namespace DeadDrop\ControlPlane;

/**
 * Account + device API (ADR-022): register, login, the username -> active-device directory, and the
 * device-management endpoints (add / list / revoke). Every key that crosses the wire is a 64-char
 * lowercase hex string (a device''s public identity key or a SHA-256 of a client-side secret); a
 * device id is a 32-char hex handle the server mints. `mixed` enters only at the request boundary
 * and is narrowed immediately (§6). Each handler returns [httpStatus, jsonBody].
 */
final class Api
{
    private const int AWAY_TEXT_MAX = 560;
    private const PRESENCE_STATUSES = ['online', 'away', 'idle'];

    public function __construct(private readonly UserStore $store)
    {
    }

    /**
     * Create an account and its first device.
     *
     * RESIDUAL, deliberately not fixed: the 409-vs-201 split is an unauthenticated account-existence
     * oracle. It is structural, not a bug - usernames must be unique and registration cannot be
     * authenticated (there is nobody to authenticate yet), so the caller must be told the name is
     * taken. Faking a 201 would break the client's taken-branch (auth.ts RegisterResult.taken) and hand
     * the user an account they cannot log into, trading a documented leak for a broken product. The
     * practical enumeration path was never this one anyway: it pays a full Argon2id hash per probe,
     * where /api/lookup used to cost a single SELECT. That is the one this change closes down.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function register(array $body): array
    {
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        $authSecret = self::hex64($body['authSecret'] ?? null);
        $deviceKey = self::hex64($body['identityKey'] ?? null); // the first device''s key
        $authSecretV2 = self::hex64($body['authSecretV2'] ?? null);
        if ($usernameHash === null || $authSecret === null || $deviceKey === null) {
            return [400, ['error' => 'invalid_request']];
        }
        // Proof of work. This does not protect the server's CPU (a v2 registration costs it nothing);
        // it prices ACCOUNT MINTING, because a free account carries a directory-probe budget and an
        // attacker who wants a bigger budget simply makes more accounts. One HMAC and one hash to check.
        $pow = $body['pow'] ?? null;
        if (!is_array($pow)) {
            return [400, ['error' => 'proof_of_work_required']];
        }
        $ok = $this->store->spendChallenge(
            is_string($pow['challenge'] ?? null) ? $pow['challenge'] : '',
            is_numeric($pow['expiresAt'] ?? null) ? (int) $pow['expiresAt'] : 0,
            is_string($pow['mac'] ?? null) ? $pow['mac'] : '',
            is_string($pow['nonce'] ?? null) ? $pow['nonce'] : '',
        );
        if (!$ok) {
            return [400, ['error' => 'proof_of_work_required']];
        }
        $deviceId = $this->store->register($usernameHash, $authSecret, $deviceKey, $authSecretV2);
        if ($deviceId === null) {
            return [409, ['error' => 'username_taken']];
        }
        return [201, ['token' => $this->store->createSession($usernameHash, $deviceId), 'deviceId' => $deviceId]];
    }

    /**
     * Issue a proof-of-work challenge for registration. Unauthenticated by necessity (registration is),
     * and cheap on purpose: one random value and one HMAC, no stored state until a challenge is spent.
     * Minting challenges freely buys nothing, because each still has to be solved to be redeemed.
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function challenge(): array
    {
        return [200, $this->store->issueChallenge()];
    }

    /**
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function login(array $body): array
    {
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        $authSecret = self::hex64($body['authSecret'] ?? null);
        $authSecretV2 = self::hex64($body['authSecretV2'] ?? null);
        if ($usernameHash === null || $authSecret === null) {
            return [400, ['error' => 'invalid_request']];
        }
        // Bound stuffing against ONE account. Answers exactly like a wrong passphrase, so it tells a
        // caller nothing they did not already know (they chose the username), and it needs no address.
        // No per-account attempt limiter here, deliberately: see the note in UserStore where one used to
        // live. Every credential is verified, so a correct passphrase always works and a wrong one always
        // costs the same as an unknown account.
        if (!$this->store->authenticate($usernameHash, $authSecret, $authSecretV2)) {
            return [401, ['error' => 'unauthorized']];
        }
        // Opportunistically sweep this account's abandoned never-authorized device rows (best-effort; a
        // busy DB just retries on the next login).
        try {
            $this->store->reapOrphanDevices($usernameHash);
        } catch (\Throwable $e) {
            // ignore: reaping must never fail a login
        }
        // The session is unbound until this device enrolls (add-device carries the device key).
        return [200, ['token' => $this->store->createSession($usernameHash)]];
    }

    /**
     * Directory lookup: the username''s active device keys plus the device that should receive (the
     * single-active routing model, ADR-022). Requires a live session.
     *
     * ONE response shape, always 200. An unknown account, an account whose every device is revoked, and
     * a caller who has spent their probe budget all return the same empty device list. Distinguishing
     * them (the old 404) made this the cheapest enumeration endpoint in the system: no Argon2, a pure
     * SELECT, and a session is free because registration is free. It is still an oracle to anyone
     * willing to spend probe budget - a hit lists keys and a miss does not, which no uniform shape can
     * hide - but the answer now costs budget instead of nothing, and a throttled caller cannot tell
     * their negatives apart from real ones.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function lookup(array $body): array
    {
        $caller = $this->account($body);
        if ($caller === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        if ($usernameHash === null) {
            return [400, ['error' => 'invalid_request']];
        }
        if (!$this->store->allowProbe($caller)) {
            return self::emptyDirectory();
        }
        $active = $this->store->lookupActive($usernameHash);
        if ($active === null) {
            return self::emptyDirectory();
        }
        return [200, ['activeDeviceKey' => $active['activeDeviceKey'], 'deviceKeys' => $active['deviceKeys']]];
    }

    /**
     * The single directory miss shape, shared by "no such account", "no active devices" and "probe
     * budget exhausted" so none of the three can be told apart.
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    private static function emptyDirectory(): array
    {
        return [200, ['activeDeviceKey' => null, 'deviceKeys' => []]];
    }

    /**
     * Enroll the calling device under its account. Two factors: a live session token AND the
     * re-presented auth secret, so a stolen token alone cannot add a device. Idempotent on the key.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function addDevice(array $body): array
    {
        $token = self::token($body);
        $ctx = $token === null ? null : $this->store->sessionContext($token);
        if ($token === null || $ctx === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $authSecret = self::hex64($body['authSecret'] ?? null);
        $deviceKey = self::hex64($body['deviceKey'] ?? null);
        if ($authSecret === null || $deviceKey === null) {
            return [400, ['error' => 'invalid_request']];
        }
        if (!$this->store->authenticate($ctx['account'], $authSecret)) {
            return [401, ['error' => 'unauthorized']];
        }
        // Sweep aged never-authorized orphans BEFORE the upsert (so the freshly upserted row, last_seen_at
        // = now, can never self-reap), excluding this session's own bound device so we do not delete the
        // row and session the caller is using.
        try {
            $this->store->reapOrphanDevices($ctx['account'], $ctx['deviceId'] ?? null);
        } catch (\Throwable $e) {
            // ignore: reaping must never fail an add-device
        }
        [$status, $deviceId] = $this->store->upsertDevice($ctx['account'], $deviceKey);
        if ($status === 'taken') {
            return [409, ['error' => 'device_key_taken']];
        }
        if ($status === 'revoked') {
            return [409, ['error' => 'device_revoked']];
        }
        if ($deviceId !== null) {
            $this->store->bindSessionDevice($token, $deviceId);
        }
        return [$status === 'created' ? 201 : 200, ['deviceId' => $deviceId]];
    }

    /**
     * List the caller''s own devices for the management screen, marking the current device.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function listDevices(array $body): array
    {
        $token = self::token($body);
        $ctx = $token === null ? null : $this->store->sessionContext($token);
        if ($ctx === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $devices = [];
        foreach ($this->store->listDevices($ctx['account']) as $d) {
            $devices[] = [...$d, 'current' => $ctx['deviceId'] !== null && $d['deviceId'] === $ctx['deviceId']];
        }
        // accountEpoch rides along because this is the call the client already makes before pairing, and
        // it needs the epoch to MINT the new device's certificate at. It used to count the revoked rows
        // in this same response, which tied a security floor to how much history happened to be kept.
        // accountEpoch and revocations both ride along because this is the call the client already makes
        // before pairing. The epoch is the number it MINTS at; the revocations are the ADR-022 P7
        // denylist, and they are the part that actually authorizes: a revoked device that still holds
        // the account seed re-certifies itself above any epoch, so exclusion has to name the device.
        // Sending them here means a client cannot pair without first seeing them.
        return [200, [
            'devices' => $devices,
            'accountEpoch' => $this->store->accountEpoch($ctx['account']),
            'revocations' => $this->store->listRevocations($ctx['account']),
        ]];
    }

    /**
     * Revoke one of the caller''s devices: burn its key and cut its sessions. Idempotent.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function revokeDevice(array $body): array
    {
        $account = $this->account($body);
        if ($account === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $deviceId = self::hex32($body['deviceId'] ?? null);
        if ($deviceId === null) {
            return [400, ['error' => 'invalid_request']];
        }
        if ($this->store->revokeDevice($account, $deviceId) === 'not_found') {
            return [404, ['error' => 'not_found']];
        }
        // ADR-022 P7: the client (a seed-holder) also sends a SIGNED revocation record naming the
        // device's signature key, which is what every other device checks at its gate. Stored
        // best-effort and reported back: burning the server-side row already succeeded and must not be
        // undone by a record this server cannot judge anyway, but the client needs to know whether the
        // durable half landed so it can retry rather than assume the device is excluded everywhere.
        // Optional, so a client that predates P7 (or a device without the account key) still revokes.
        $record = $body['record'] ?? null;
        $stored = is_string($record) && $this->store->addRevocation($account, $record);
        return [200, ['ok' => true, 'recordStored' => $stored]];
    }

    /**
     * The caller''s ADR-022 P7 revocation records. Separate from list-devices so a client can refresh
     * the denylist on its own schedule (login, reconnect) without pulling the device table, and so a
     * device that is not authorized to manage devices can still learn who was thrown out.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function listRevocations(array $body): array
    {
        $account = $this->account($body);
        if ($account === null) {
            return [401, ['error' => 'unauthorized']];
        }
        return [200, ['revocations' => $this->store->listRevocations($account)]];
    }

    /**
     * Self destruct: permanently delete the caller''s entire account from the server. Removes the
     * account row, every device (so all device keys are burned), every key package, every session,
     * and any server-side away / presence state. Authorized by the caller''s own session token, so a
     * user can only destroy their own account. Idempotent (deleting an already-gone account is ok).
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function deleteAccount(array $body): array
    {
        $account = $this->account($body);
        if ($account === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $this->store->deleteAccount($account);
        return [200, ['ok' => true]];
    }

    /**
     * Publish this device''s one-time key packages (pre-keys) so it can be added to MLS groups
     * without a live handshake. Requires a device-bound session (the device must have enrolled).
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function publishKeys(array $body): array
    {
        $token = self::token($body);
        $ctx = $token === null ? null : $this->store->sessionContext($token);
        if ($ctx === null) {
            return [401, ['error' => 'unauthorized']];
        }
        if ($ctx['deviceId'] === null) {
            return [409, ['error' => 'device_not_enrolled']]; // add-device must run first
        }
        $packages = self::keyPackages($body['keyPackages'] ?? null);
        if ($packages === null) {
            return [400, ['error' => 'invalid_request']];
        }
        $stored = $this->store->publishKeyPackages($ctx['account'], $ctx['deviceId'], $packages);
        return [201, ['stored' => $stored]];
    }

    /**
     * Claim one key package per active device of a username, to bootstrap a group with all of that
     * user''s devices. Each one-time package is consumed; a device with none falls back to its
     * reusable last-resort package (flagged). Requires a live session.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function takeKeys(array $body): array
    {
        $caller = $this->account($body);
        if ($caller === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        if ($usernameHash === null) {
            return [400, ['error' => 'invalid_request']];
        }
        // Spend probe budget first: take-keys is a directory read like lookup (a target with no active
        // device answers with an empty list), so it must not be a way to enumerate around the throttle.
        // A denial answers as a miss - an empty device list, never 429 - so it cannot be told apart from
        // "that account has no devices". The honest cost: a client that somehow exhausted its budget
        // sees a reachable peer as deviceless. At 120 probes/minute no real client gets there.
        if (!$this->store->allowProbe($caller)) {
            return [200, ['devices' => []]];
        }
        // The separate per-caller->per-target claim ceiling: bounds a tight loop draining ONE target's
        // one-time prekeys (prekey exhaustion). It answers as a miss too, for a reason that is easy to
        // miss: this check runs AFTER the probe budget, so an explicit 429 here would have said "the
        // probe budget is still available" while a plain empty list said "it is exhausted". That is a
        // statistics-free read of throttle state from an endpoint whose whole point is to give none.
        // Both denials now look exactly like an account with no devices. The cost is that a client that
        // drains one target's prekeys sees them as deviceless instead of being told to slow down.
        if (!$this->store->allowTake($caller, $usernameHash)) {
            return [200, ['devices' => []]];
        }
        return [200, ['devices' => $this->store->takeKeyPackages($usernameHash)]];
    }

    /**
     * Server-side away (opt-in): store the caller''s away text (empty clears it). The away text is
     * SERVER-READABLE plaintext, the documented zero-knowledge relaxation (honest-limits). Requires a
     * live session.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function setAway(array $body): array
    {
        $account = $this->account($body);
        if ($account === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $text = $body['awayText'] ?? null;
        if (!is_string($text) || mb_strlen($text) > self::AWAY_TEXT_MAX) {
            return [400, ['error' => 'invalid_request']];
        }
        if (trim($text) === '') {
            $this->store->clearAway($account);
            return [200, ['ok' => true, 'away' => false]];
        }
        $this->store->setAway($account, $text);
        return [200, ['ok' => true, 'away' => true]];
    }

    /**
     * Heartbeat: refresh the caller''s live marker so their away text is not served while a device is
     * online. A no-op when server-side away is off. Requires a live session.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function awayBeat(array $body): array
    {
        $account = $this->account($body);
        if ($account === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $this->store->beatAway($account);
        return [200, ['ok' => true]];
    }

    /**
     * A sender looks up a username''s away message. Returns the away text only when away is on AND every
     * device is offline; null otherwise. Requires a live session (like the directory lookup). Honest
     * limit: this reveals to the server that the caller reached an offline account (honest-limits).
     *
     * Honest limit, unchanged and NOT fixed here: any caller who knows a username hash reads that
     * account''s away text, which the server stores in plaintext. There is no reciprocity check, and
     * there will not be one - the server would have to learn who is on whose buddy list to enforce it,
     * trading the documented "no contact graph" property (P2) for an undocumented one. The probe budget
     * below bounds bulk collection; it does not make the text private.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function awayLookup(array $body): array
    {
        $caller = $this->account($body);
        if ($caller === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        if ($usernameHash === null) {
            return [400, ['error' => 'invalid_request']];
        }
        // A denial is the same 200 + null an account with away off (or an unknown account) returns.
        if (!$this->store->allowProbe($caller)) {
            return [200, ['away' => null]];
        }
        return [200, ['away' => $this->store->lookupAway($usernameHash)]];
    }

    /**
     * Presence (opt-in): set this account''s shared status (online/away/idle) and refresh the heartbeat.
     * Server-readable, the documented relaxation (honest-limits). Requires a live session.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function setPresence(array $body): array
    {
        $account = $this->account($body);
        if ($account === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $status = $body['status'] ?? null;
        if (!is_string($status) || !in_array($status, self::PRESENCE_STATUSES, true)) {
            return [400, ['error' => 'invalid_request']];
        }
        $this->store->setPresence($account, $status);
        return [200, ['ok' => true]];
    }

    /**
     * Presence opt-out: turn presence off so buddies read this account as offline. Requires a session.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function clearPresence(array $body): array
    {
        $account = $this->account($body);
        if ($account === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $this->store->clearPresence($account);
        return [200, ['ok' => true]];
    }

    /**
     * A buddy reads a username''s presence: online/away/idle when fresh, else offline. Requires session.
     *
     * Honest limit: polling this for many hashes on a timer builds an online/offline timeline for the
     * whole opted-in user base. Like away, it has no reciprocity check by design (that would require a
     * server-side contact graph). The probe budget is what makes mass polling expensive.
     *
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function getPresence(array $body): array
    {
        $caller = $this->account($body);
        if ($caller === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        if ($usernameHash === null) {
            return [400, ['error' => 'invalid_request']];
        }
        // 'offline' is exactly what an unknown account, an opted-out account and a stale heartbeat
        // return, so a throttled poll is indistinguishable from all three.
        if (!$this->store->allowProbe($caller)) {
            return [200, ['status' => 'offline']];
        }
        return [200, ['status' => $this->store->getPresence($usernameHash)]];
    }

    /**
     * Validate and narrow a published key-package list.
     *
     * @return list<array{blob: string, ref: string, lastResort: bool}>|null
     */
    private static function keyPackages(mixed $value): ?array
    {
        if (!is_array($value) || $value === [] || count($value) > 200) {
            return null;
        }
        $out = [];
        foreach ($value as $entry) {
            if (!is_array($entry)) {
                return null;
            }
            $blob = $entry['keyPackage'] ?? null;
            $ref = self::hex64($entry['ref'] ?? null);
            $lastResort = $entry['lastResort'] ?? false;
            // The blob is an opaque MLS KeyPackage as lowercase hex (the server never parses it).
            if (!is_string($blob) || preg_match('/^[0-9a-f]{2,40000}$/', $blob) !== 1 || strlen($blob) % 2 !== 0) {
                return null;
            }
            if ($ref === null || !is_bool($lastResort)) {
                return null;
            }
            $out[] = ['blob' => $blob, 'ref' => $ref, 'lastResort' => $lastResort];
        }
        return $out;
    }

    /**
     * The account behind a request''s session token, or null if there is no live session.
     *
     * @param array<array-key, mixed> $body
     */
    private function account(array $body): ?string
    {
        $token = self::token($body);
        return $token === null ? null : $this->store->sessionUser($token);
    }

    /** @param array<array-key, mixed> $body */
    private static function token(array $body): ?string
    {
        $token = $body['token'] ?? null;
        return is_string($token) && $token !== '' ? $token : null;
    }

    private static function hex64(mixed $value): ?string
    {
        return is_string($value) && preg_match('/^[0-9a-f]{64}$/', $value) === 1 ? $value : null;
    }

    private static function hex32(mixed $value): ?string
    {
        return is_string($value) && preg_match('/^[0-9a-f]{32}$/', $value) === 1 ? $value : null;
    }
}
