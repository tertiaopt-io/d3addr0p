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
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function register(array $body): array
    {
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        $authSecret = self::hex64($body['authSecret'] ?? null);
        $deviceKey = self::hex64($body['identityKey'] ?? null); // the first device''s key
        if ($usernameHash === null || $authSecret === null || $deviceKey === null) {
            return [400, ['error' => 'invalid_request']];
        }
        $deviceId = $this->store->register($usernameHash, $authSecret, $deviceKey);
        if ($deviceId === null) {
            return [409, ['error' => 'username_taken']];
        }
        return [201, ['token' => $this->store->createSession($usernameHash, $deviceId), 'deviceId' => $deviceId]];
    }

    /**
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function login(array $body): array
    {
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        $authSecret = self::hex64($body['authSecret'] ?? null);
        if ($usernameHash === null || $authSecret === null) {
            return [400, ['error' => 'invalid_request']];
        }
        if (!$this->store->authenticate($usernameHash, $authSecret)) {
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
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function lookup(array $body): array
    {
        if ($this->account($body) === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        if ($usernameHash === null) {
            return [400, ['error' => 'invalid_request']];
        }
        $active = $this->store->lookupActive($usernameHash);
        if ($active === null) {
            return [404, ['error' => 'not_found']];
        }
        return [200, ['activeDeviceKey' => $active['activeDeviceKey'], 'deviceKeys' => $active['deviceKeys']]];
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
        return [200, ['devices' => $devices]];
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
        return [200, ['ok' => true]];
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
        // Throttle a tight loop of claims against one target so a single caller cannot rapidly drain
        // its one-time prekeys (prekey exhaustion). Legitimate group bootstrapping is far under the cap.
        if (!$this->store->allowTake($caller, $usernameHash)) {
            return [429, ['error' => 'rate_limited']];
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
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function awayLookup(array $body): array
    {
        if ($this->account($body) === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        if ($usernameHash === null) {
            return [400, ['error' => 'invalid_request']];
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
     * @param array<array-key, mixed> $body
     * @return array{0: int, 1: array<string, mixed>}
     */
    public function getPresence(array $body): array
    {
        if ($this->account($body) === null) {
            return [401, ['error' => 'unauthorized']];
        }
        $usernameHash = self::hex64($body['usernameHash'] ?? null);
        if ($usernameHash === null) {
            return [400, ['error' => 'invalid_request']];
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
