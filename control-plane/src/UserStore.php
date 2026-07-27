<?php

declare(strict_types=1);

namespace DeadDrop\ControlPlane;

use PDO;
use Throwable;

/**
 * Account registry + authentication + the per-account device registry (ADR-022).
 *
 * The server holds only client-computed hashes (a username hash and an Argon2id verifier over a
 * client-derived auth secret) plus, per device, that device''s public identity key. It never sees a
 * plaintext username, the passphrase, a device name, or any message. An account has one or more
 * devices; registration creates the account and its first device atomically. A device key is
 * globally unique and stays burned once revoked, so it can never be re-claimed or re-enrolled.
 */
final class UserStore
{
    private const int SESSION_TTL = 86400 * 7; // 7 days
    private const int AWAY_OFFLINE_TTL = 90; // seconds without a heartbeat before an account counts offline
    private const int PRESENCE_TTL = 90; // seconds without a presence heartbeat before a buddy reads offline
    private const int TAKE_WINDOW = 60; // seconds: the fixed rate window for cross-user key-package claims
    private const int TAKE_MAX_PER_WINDOW = 30; // claims per caller->target per window (well above legit use)
    private const int ORPHAN_GRACE = 600; // seconds an enrolled-but-never-authorized device row may linger before reaping

    public function __construct(
        private readonly PDO $pdo,
        private readonly int $now,
    ) {
    }

    /**
     * Create an account with its first device. Returns the new device id, or null if the username
     * hash is already taken. Atomic: an account never exists without at least one device.
     */
    public function register(string $usernameHash, string $authSecret, string $deviceKey): ?string
    {
        $authHash = password_hash($authSecret, PASSWORD_ARGON2ID);
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare('INSERT OR IGNORE INTO users (username_hash, auth_hash, created_at) VALUES (?, ?, ?)');
            $stmt->execute([$usernameHash, $authHash, $this->now]);
            if ($stmt->rowCount() !== 1) {
                $this->pdo->rollBack();
                return null; // the username hash already exists
            }
            $deviceId = $this->insertDevice($usernameHash, $deviceKey);
            $this->pdo->commit();
            return $deviceId;
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /** A fixed Argon2id hash with the same cost params as register(), computed once per worker and
     *  cached, so the account-not-found path can pay an identical verify cost without leaking timing. */
    private static ?string $dummyAuthHash = null;

    /** Verify a login or a device-enrollment proof. True only when the account exists and matches. */
    public function authenticate(string $usernameHash, string $authSecret): bool
    {
        $stmt = $this->pdo->prepare('SELECT auth_hash FROM users WHERE username_hash = ?');
        $stmt->execute([$usernameHash]);
        $row = $stmt->fetch();
        $authHash = is_array($row) ? ($row['auth_hash'] ?? null) : null;
        if (!is_string($authHash)) {
            // Account does not exist. Still run one Argon2id verify against a fixed dummy hash (same
            // cost params as register) so the response time does not reveal existence: without this,
            // a missing account returns in microseconds while a real one pays tens of ms, an
            // unauthenticated account-existence oracle over candidate username hashes. Result discarded.
            self::$dummyAuthHash ??= password_hash('deaddrop-dummy-authsecret', PASSWORD_ARGON2ID);
            password_verify($authSecret, self::$dummyAuthHash);
            return false;
        }
        return password_verify($authSecret, $authHash);
    }

    /**
     * Enroll a device under an account, idempotent on the device key.
     *
     * @return array{0: 'created'|'exists'|'revoked'|'taken', 1: ?string} status + the device id
     *   ('taken' when the key belongs to another account; 'revoked' when it was revoked and burned)
     */
    public function upsertDevice(string $account, string $deviceKey): array
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare('SELECT device_id, account, revoked_at FROM devices WHERE device_pub = ?');
            $stmt->execute([$deviceKey]);
            $row = $stmt->fetch();
            if (is_array($row)) {
                $deviceId = is_string($row['device_id'] ?? null) ? $row['device_id'] : '';
                if (($row['account'] ?? null) !== $account) {
                    $this->pdo->commit();
                    return ['taken', null]; // this key is registered to a different account
                }
                if (($row['revoked_at'] ?? null) !== null) {
                    $this->pdo->commit();
                    return ['revoked', $deviceId];
                }
                $this->pdo->prepare('UPDATE devices SET last_seen_at = ? WHERE device_id = ?')->execute([$this->now, $deviceId]);
                $this->pdo->commit();
                return ['exists', $deviceId];
            }
            $deviceId = $this->insertDevice($account, $deviceKey);
            $this->pdo->commit();
            return ['created', $deviceId];
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Every device on the account (active and revoked), oldest first, for the management screen.
     *
     * `authorized` = the device has published at least one key package (a one-time or the reusable
     * last-resort), the exact discriminator for a real device versus an enrolled-but-never-authorized
     * orphan. The client uses it so the last-device revoke guard counts only real devices.
     *
     * @return list<array{deviceId: string, deviceKey: string, addedAt: int, lastSeenAt: int, revoked: bool, authorized: bool}>
     */
    public function listDevices(string $account): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT device_id, device_pub, added_at, last_seen_at, revoked_at, '
            . 'EXISTS(SELECT 1 FROM key_packages kp WHERE kp.device_id = devices.device_id) AS has_keys '
            . 'FROM devices WHERE account = ? ORDER BY added_at'
        );
        $stmt->execute([$account]);
        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            if (!is_array($row)) {
                continue;
            }
            $id = $row['device_id'] ?? null;
            $pub = $row['device_pub'] ?? null;
            if (!is_string($id) || !is_string($pub)) {
                continue;
            }
            $added = $row['added_at'] ?? null;
            $lastSeen = $row['last_seen_at'] ?? null;
            $hasKeys = $row['has_keys'] ?? null;
            $out[] = [
                'deviceId' => $id,
                'deviceKey' => $pub,
                'addedAt' => is_numeric($added) ? (int) $added : 0,
                'lastSeenAt' => is_numeric($lastSeen) ? (int) $lastSeen : 0,
                'revoked' => ($row['revoked_at'] ?? null) !== null,
                'authorized' => (is_numeric($hasKeys) ? (int) $hasKeys : 0) === 1,
            ];
        }
        return $out;
    }

    /**
     * Revoke a device on this account: burn its key and delete its live sessions. Idempotent.
     *
     * @return 'revoked'|'not_found' not_found when the device id is unknown or not on this account
     */
    public function revokeDevice(string $account, string $deviceId): string
    {
        $this->pdo->beginTransaction();
        try {
            $check = $this->pdo->prepare('SELECT 1 FROM devices WHERE device_id = ? AND account = ?');
            $check->execute([$deviceId, $account]);
            if ($check->fetch() === false) {
                $this->pdo->commit();
                return 'not_found';
            }
            $this->pdo->prepare('UPDATE devices SET revoked_at = ? WHERE device_id = ? AND account = ? AND revoked_at IS NULL')
                ->execute([$this->now, $deviceId, $account]);
            $this->pdo->prepare('DELETE FROM sessions WHERE device_id = ?')->execute([$deviceId]);
            $this->pdo->prepare('DELETE FROM key_packages WHERE device_id = ?')->execute([$deviceId]);
            $this->pdo->commit();
            return 'revoked';
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Reap orphan device rows: enrolled-but-never-authorized devices (no key package ever published) that
     * have not been seen for ORPHAN_GRACE seconds, left behind by abandoned add-a-device attempts. DELETE,
     * never revoke: a reaped innocent key must be able to re-enroll as 'created', not hit the burned-key
     * 409. INVARIANTS: only rows with NO key_packages AND revoked_at IS NULL are touched, so a revoked
     * tombstone (which feeds the P6 epoch floor) is never deleted and the revoked-row count is invariant.
     * Ages on last_seen_at (refreshed on every re-login via upsertDevice's 'exists' branch), so a device
     * that keeps signing in is safe. $excludeDeviceId shields the caller's own bound row from a mid-call
     * reap. Best-effort; returns the number of rows deleted.
     */
    public function reapOrphanDevices(string $account, ?string $excludeDeviceId = null): int
    {
        $this->pdo->beginTransaction();
        try {
            $cutoff = $this->now - self::ORPHAN_GRACE;
            $sql = 'SELECT device_id FROM devices d WHERE d.account = ? AND d.revoked_at IS NULL '
                . 'AND d.last_seen_at <= ? AND NOT EXISTS (SELECT 1 FROM key_packages kp WHERE kp.device_id = d.device_id)';
            $params = [$account, $cutoff];
            if ($excludeDeviceId !== null) {
                $sql .= ' AND d.device_id != ?';
                $params[] = $excludeDeviceId;
            }
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            $ids = array_column($stmt->fetchAll(), 'device_id');
            $delSession = $this->pdo->prepare('DELETE FROM sessions WHERE device_id = ?');
            $delDevice = $this->pdo->prepare('DELETE FROM devices WHERE device_id = ?');
            foreach ($ids as $id) {
                // Delete the sessions in the same transaction: sessionContext's LEFT JOIN reads a missing
                // device row as revoked_at IS NULL (alive), so an orphaned session would otherwise persist.
                $delSession->execute([$id]);
                $delDevice->execute([$id]);
            }
            $this->pdo->commit();
            return count($ids);
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Self destruct: permanently delete an entire account and everything tied to it. Removes every
     * device (burning all device keys), every key package, every session, the away and presence rows,
     * and finally the account itself. One transaction, so it is all-or-nothing. Idempotent: deleting
     * an account that is already gone simply removes nothing.
     */
    public function deleteAccount(string $account): void
    {
        $this->pdo->beginTransaction();
        try {
            $this->pdo->prepare('DELETE FROM key_packages WHERE account = ?')->execute([$account]);
            $this->pdo->prepare('DELETE FROM sessions WHERE username_hash = ?')->execute([$account]);
            $this->pdo->prepare('DELETE FROM devices WHERE account = ?')->execute([$account]);
            $this->pdo->prepare('DELETE FROM away WHERE account = ?')->execute([$account]);
            $this->pdo->prepare('DELETE FROM presence WHERE account = ?')->execute([$account]);
            $this->pdo->prepare('DELETE FROM users WHERE username_hash = ?')->execute([$account]);
            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Directory lookup: the account''s active device keys plus the active device that should receive
     * (the most recently seen). Null if the account has no active device.
     *
     * @return array{deviceKeys: list<string>, activeDeviceKey: string}|null
     */
    public function lookupActive(string $account): ?array
    {
        // Most recently seen wins; rowid breaks a same-timestamp tie so the newer device is active.
        $stmt = $this->pdo->prepare(
            'SELECT device_pub FROM devices WHERE account = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC, added_at DESC, rowid DESC'
        );
        $stmt->execute([$account]);
        $keys = [];
        foreach ($stmt->fetchAll() as $row) {
            if (is_array($row) && is_string($row['device_pub'] ?? null)) {
                $keys[] = $row['device_pub'];
            }
        }
        if ($keys === []) {
            return null;
        }
        return ['deviceKeys' => $keys, 'activeDeviceKey' => $keys[0]];
    }

    /** Issue an opaque session token, optionally bound to the device that authenticated. */
    public function createSession(string $usernameHash, ?string $deviceId = null): string
    {
        $token = bin2hex(random_bytes(32));
        $stmt = $this->pdo->prepare('INSERT INTO sessions (token, username_hash, device_id, expires_at) VALUES (?, ?, ?, ?)');
        $stmt->execute([$token, $usernameHash, $deviceId, $this->now + self::SESSION_TTL]);
        return $token;
    }

    /** Bind an existing session to a device (after the device enrolls), so revoke can cut it off. */
    public function bindSessionDevice(string $token, string $deviceId): void
    {
        $this->pdo->prepare('UPDATE sessions SET device_id = ? WHERE token = ?')->execute([$deviceId, $token]);
    }

    /** The account a session token belongs to, or null if unknown or expired. */
    public function sessionUser(string $token): ?string
    {
        $ctx = $this->sessionContext($token);
        return $ctx === null ? null : $ctx['account'];
    }

    /**
     * The account and bound device of a live session, or null if unknown or expired.
     *
     * @return array{account: string, deviceId: ?string}|null
     */
    public function sessionContext(string $token): ?array
    {
        // A session bound to a REVOKED device reads as dead (defence in depth for the bind-races-revoke
        // TOCTOU: revokeDevice already deletes the device's sessions, but a bindSessionDevice landing just
        // after that DELETE would otherwise leave a live token on a burned device). The
        // `s.device_id IS NULL` arm keeps an UNBOUND fresh login alive, so legitimate re-login on any
        // device still works; only a session whose bound device carries revoked_at is nulled.
        $stmt = $this->pdo->prepare(
            'SELECT s.username_hash, s.device_id, s.expires_at
               FROM sessions s
               LEFT JOIN devices d ON d.device_id = s.device_id
              WHERE s.token = ? AND (s.device_id IS NULL OR d.revoked_at IS NULL)'
        );
        $stmt->execute([$token]);
        $row = $stmt->fetch();
        if (!is_array($row)) {
            return null;
        }
        $account = $row['username_hash'] ?? null;
        $expiresAt = $row['expires_at'] ?? null;
        if (!is_string($account) || !is_numeric($expiresAt)) {
            return null;
        }
        if ((int) $expiresAt <= $this->now) {
            $this->deleteSession($token);
            return null;
        }
        $deviceId = $row['device_id'] ?? null;
        return ['account' => $account, 'deviceId' => is_string($deviceId) ? $deviceId : null];
    }

    public function deleteSession(string $token): void
    {
        $this->pdo->prepare('DELETE FROM sessions WHERE token = ?')->execute([$token]);
    }

    /**
     * Turn on server-side away for an account: store the away text and mark the account currently live
     * (a fresh heartbeat), so the text is NOT served until the account goes offline. Upsert. The away
     * text is server-readable plaintext (the documented zero-knowledge relaxation).
     */
    public function setAway(string $account, string $text): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO away (account, away_text, last_beat_at, updated_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(account) DO UPDATE SET away_text = excluded.away_text, last_beat_at = excluded.last_beat_at, updated_at = excluded.updated_at'
        );
        $stmt->execute([$account, $text, $this->now, $this->now]);
    }

    /** Turn off server-side away for an account (delete the row). Idempotent. */
    public function clearAway(string $account): void
    {
        $this->pdo->prepare('DELETE FROM away WHERE account = ?')->execute([$account]);
    }

    /** Heartbeat: mark the account currently live so its away text is not served while a device is on.
     * A no-op when server-side away is off (no row). */
    public function beatAway(string $account): void
    {
        $this->pdo->prepare('UPDATE away SET last_beat_at = ? WHERE account = ?')->execute([$this->now, $account]);
    }

    /**
     * The away text to serve to a sender, or null when away is off OR the account is currently live (a
     * heartbeat within the TTL). Server-side away answers only once every device is offline; while a
     * device is online the client-side auto-reply handles it.
     */
    public function lookupAway(string $account): ?string
    {
        $stmt = $this->pdo->prepare('SELECT away_text, last_beat_at FROM away WHERE account = ?');
        $stmt->execute([$account]);
        $row = $stmt->fetch();
        if (!is_array($row)) {
            return null;
        }
        $text = $row['away_text'] ?? null;
        $beat = $row['last_beat_at'] ?? null;
        if (!is_string($text) || !is_numeric($beat)) {
            return null;
        }
        if ($this->now - (int) $beat < self::AWAY_OFFLINE_TTL) {
            return null; // a device is still live -> the client-side away handles replies
        }
        return $text;
    }

    /** Set the opt-in presence status (online/away/idle) and refresh the heartbeat. Upsert. The server
     * is now able to read this status, which is the documented presence relaxation. */
    public function setPresence(string $account, string $status): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO presence (account, status, last_beat_at) VALUES (?, ?, ?)
             ON CONFLICT(account) DO UPDATE SET status = excluded.status, last_beat_at = excluded.last_beat_at'
        );
        $stmt->execute([$account, $status, $this->now]);
    }

    /** Turn presence off for an account (delete the row), so buddies read it as offline. Idempotent. */
    public function clearPresence(string $account): void
    {
        $this->pdo->prepare('DELETE FROM presence WHERE account = ?')->execute([$account]);
    }

    /** The presence status to show a buddy: the stored status when fresh, else 'offline' (off or stale). */
    public function getPresence(string $account): string
    {
        $stmt = $this->pdo->prepare('SELECT status, last_beat_at FROM presence WHERE account = ?');
        $stmt->execute([$account]);
        $row = $stmt->fetch();
        if (!is_array($row)) {
            return 'offline';
        }
        $status = $row['status'] ?? null;
        $beat = $row['last_beat_at'] ?? null;
        if (!is_string($status) || !is_numeric($beat) || $this->now - (int) $beat >= self::PRESENCE_TTL) {
            return 'offline';
        }
        return $status;
    }

    /**
     * Publish one-time key packages for a device (idempotent per (device, ref)). A last-resort
     * package replaces the device''s existing one. Returns how many new packages were stored.
     *
     * @param list<array{blob: string, ref: string, lastResort: bool}> $packages
     */
    public function publishKeyPackages(string $account, string $deviceId, array $packages): int
    {
        // All-or-nothing: the batch (including the last-resort replace DELETE+INSERT) runs in one
        // transaction so a reader (the last-device revoke guard, or the orphan reaper's NOT EXISTS check)
        // never observes a transient zero-key-package window that would flip authorized to false. A future
        // caller already inside a UserStore transaction must share the outer txn (PDO forbids nesting); the
        // sole caller today is Api::publishKeys, never in a transaction.
        $this->pdo->beginTransaction();
        try {
            // A publish REPLACES the device's unconsumed one-time backlog: the fresh batch carries the
            // device's CURRENT credential, while old unconsumed rows may carry a stale one (a package
            // minted before the device was authorized becomes a certless roster leaf nothing can
            // repair). Serving oldest-first from an unbounded backlog is exactly how a poisoned
            // package outlives its fix, and the backlog otherwise grows by one batch per login. The
            // last-resort row is handled by its own replace below; consumed rows are history and stay.
            $this->pdo->prepare('DELETE FROM key_packages WHERE device_id = ? AND consumed_at IS NULL AND is_last_resort = 0')->execute([$deviceId]);
            $stored = 0;
            foreach ($packages as $p) {
                if ($p['lastResort']) {
                    // Exactly one last-resort per device: replace the previous one.
                    $this->pdo->prepare('DELETE FROM key_packages WHERE device_id = ? AND is_last_resort = 1')->execute([$deviceId]);
                }
                $stmt = $this->pdo->prepare(
                    'INSERT OR IGNORE INTO key_packages (kp_id, device_id, account, kp_blob, kp_ref, is_last_resort, consumed_at, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)'
                );
                $stmt->execute([
                    bin2hex(random_bytes(16)),
                    $deviceId,
                    $account,
                    $p['blob'],
                    $p['ref'],
                    $p['lastResort'] ? 1 : 0,
                    $this->now,
                ]);
                $stored += $stmt->rowCount();
            }
            $this->pdo->commit();
            return $stored;
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Fixed-window rate limit on cross-user key-package claims: bounds how fast one caller can drain a
     * target's one-time prekeys in a loop (prekey exhaustion). Consuming a target's one-times is a
     * legitimate, tested operation, so the ceiling is generous; this only throttles abusive bursts.
     * Returns true when the claim is allowed (and records it), false when the window is exhausted.
     */
    public function allowTake(string $caller, string $target): bool
    {
        $windowStart = $this->now - ($this->now % self::TAKE_WINDOW);
        $stmt = $this->pdo->prepare('SELECT window_start, count FROM take_rate WHERE caller = ? AND target = ?');
        $stmt->execute([$caller, $target]);
        $row = $stmt->fetch();
        $rowWindow = is_array($row) && is_numeric($row['window_start'] ?? null) ? (int) $row['window_start'] : null;
        $rowCount = is_array($row) && is_numeric($row['count'] ?? null) ? (int) $row['count'] : 0;
        if ($rowWindow === $windowStart) {
            if ($rowCount >= self::TAKE_MAX_PER_WINDOW) {
                return false; // this caller has hit the per-target claim ceiling for the current window
            }
            $this->pdo->prepare('UPDATE take_rate SET count = count + 1 WHERE caller = ? AND target = ?')
                ->execute([$caller, $target]);
            return true;
        }
        // First claim in a new window (or the first ever): reset the counter to 1.
        $this->pdo->prepare(
            'INSERT INTO take_rate (caller, target, window_start, count) VALUES (?, ?, ?, 1)
             ON CONFLICT(caller, target) DO UPDATE SET window_start = excluded.window_start, count = 1'
        )->execute([$caller, $target, $windowStart]);
        return true;
    }

    /**
     * Claim one key package per ACTIVE device of an account, for bootstrapping a group. Consumes a
     * one-time package per device atomically; falls back to the device''s reusable last-resort
     * package (flagged so the caller knows forward secrecy is degraded for that join). One entry per
     * active device that has any package; a device with none is skipped.
     *
     * @return list<array{deviceId: string, deviceKey: string, keyPackage: string, lastResort: bool}>
     */
    public function takeKeyPackages(string $account): array
    {
        $this->pdo->beginTransaction();
        try {
            $devices = $this->pdo->prepare('SELECT device_id, device_pub FROM devices WHERE account = ? AND revoked_at IS NULL ORDER BY added_at');
            $devices->execute([$account]);
            $out = [];
            foreach ($devices->fetchAll() as $d) {
                if (!is_array($d)) {
                    continue;
                }
                $deviceId = $d['device_id'] ?? null;
                $devicePub = $d['device_pub'] ?? null;
                if (!is_string($deviceId) || !is_string($devicePub)) {
                    continue;
                }
                $claimed = $this->claimOne($deviceId);
                if ($claimed === null) {
                    continue;
                }
                $out[] = [
                    'deviceId' => $deviceId,
                    'deviceKey' => $devicePub,
                    'keyPackage' => $claimed['blob'],
                    'lastResort' => $claimed['lastResort'],
                ];
            }
            $this->pdo->commit();
            return $out;
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /** Count a device''s unconsumed one-time key packages, so the client knows when to replenish. */
    public function keyPackageCount(string $deviceId): int
    {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM key_packages WHERE device_id = ? AND consumed_at IS NULL AND is_last_resort = 0');
        $stmt->execute([$deviceId]);
        return (int) $stmt->fetchColumn();
    }

    /**
     * Claim one package for a device: a one-time package (consumed) if available, else the reusable
     * last-resort package (flagged). Null if the device has none.
     *
     * @return array{blob: string, lastResort: bool}|null
     */
    private function claimOne(string $deviceId): ?array
    {
        $sel = $this->pdo->prepare(
            'SELECT kp_id, kp_blob FROM key_packages WHERE device_id = ? AND consumed_at IS NULL AND is_last_resort = 0 ORDER BY created_at LIMIT 1'
        );
        $sel->execute([$deviceId]);
        $row = $sel->fetch();
        if (is_array($row) && is_string($row['kp_id'] ?? null) && is_string($row['kp_blob'] ?? null)) {
            $this->pdo->prepare('UPDATE key_packages SET consumed_at = ? WHERE kp_id = ?')->execute([$this->now, $row['kp_id']]);
            return ['blob' => $row['kp_blob'], 'lastResort' => false];
        }
        $lr = $this->pdo->prepare('SELECT kp_blob FROM key_packages WHERE device_id = ? AND is_last_resort = 1 LIMIT 1');
        $lr->execute([$deviceId]);
        $lrow = $lr->fetch();
        if (is_array($lrow) && is_string($lrow['kp_blob'] ?? null)) {
            return ['blob' => $lrow['kp_blob'], 'lastResort' => true];
        }
        return null;
    }

    private function insertDevice(string $account, string $deviceKey): string
    {
        $deviceId = bin2hex(random_bytes(16));
        $stmt = $this->pdo->prepare(
            'INSERT INTO devices (device_id, account, device_pub, label, added_at, last_seen_at, revoked_at) VALUES (?, ?, ?, NULL, ?, ?, NULL)'
        );
        $stmt->execute([$deviceId, $account, $deviceKey, $this->now, $this->now]);
        return $deviceId;
    }
}
