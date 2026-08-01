<?php

declare(strict_types=1);

namespace DeadDrop\ControlPlane;

use PDO;

/**
 * SQLite-backed account store connection (account/identity tier only; never message bytes, §4).
 *
 * Stores, per account: a hash of the username (the server never sees the plaintext handle) and an
 * Argon2id verifier over a client-derived auth secret (the server never sees the passphrase). Each
 * account has one or more DEVICES (ADR-022): a device holds its own public identity key, so an
 * account can span devices and the owner can list and revoke them. The username -> key directory is
 * now a username -> active-device-keys directory. Honest limit: this registry reveals which username
 * hashes exist, how many active devices each has, and their device keys; see honest-limits.
 */
final class Db
{
    private PDO $pdo;

    public function __construct(string $path)
    {
        $this->pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->pdo->exec('PRAGMA journal_mode=WAL');
        $this->pdo->exec('PRAGMA busy_timeout=5000');
        $this->pdo->exec('PRAGMA foreign_keys=ON');
        $this->migrate();
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    private function migrate(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS users (
                username_hash TEXT PRIMARY KEY,
                auth_hash     TEXT NOT NULL,
                created_at    INTEGER NOT NULL
            )'
        );
        // One row per device. device_pub is the device''s public identity key (the old per-account
        // identity_key, now per device). label is reserved for a future client-SEALED device name;
        // the current client sends none, so the server stores no plaintext device names.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS devices (
                device_id    TEXT PRIMARY KEY,
                account      TEXT NOT NULL,
                device_pub   TEXT NOT NULL,
                label        TEXT,
                added_at     INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                revoked_at   INTEGER
            )'
        );
        // A device key is globally unique and stays burned even when revoked: it can never be
        // re-claimed by another account (anti-impersonation) or re-enrolled after revocation.
        $this->pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_pub ON devices(device_pub)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(account) WHERE revoked_at IS NULL');
        // One-time key packages (pre-keys) per device, so a device can be added to an MLS group
        // without a live handshake (ADR-022 P3). kp_blob is opaque to the server (it never parses
        // MLS); a one-time package is consumed on claim, with a reusable last-resort fallback.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS key_packages (
                kp_id          TEXT PRIMARY KEY,
                device_id      TEXT NOT NULL,
                account        TEXT NOT NULL,
                kp_blob        TEXT NOT NULL,
                kp_ref         TEXT NOT NULL,
                is_last_resort INTEGER NOT NULL DEFAULT 0,
                consumed_at    INTEGER,
                created_at     INTEGER NOT NULL
            )'
        );
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_kp_avail ON key_packages(device_id) WHERE consumed_at IS NULL AND is_last_resort = 0');
        $this->pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_kp_lastresort ON key_packages(device_id) WHERE is_last_resort = 1');
        $this->pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_kp_ref ON key_packages(device_id, kp_ref)');
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS sessions (
                token         TEXT PRIMARY KEY,
                username_hash TEXT NOT NULL,
                device_id     TEXT,
                expires_at    INTEGER NOT NULL
            )'
        );
        $this->ensureColumn('sessions', 'device_id', 'TEXT'); // pre-multi-device sessions lacked it
        // Server-side away (opt-in; see honest-limits): the account''s away message the server serves to
        // senders once every device is offline. away_text is server-readable plaintext, the documented
        // zero-knowledge relaxation; last_beat_at is the live-session heartbeat that suppresses it while
        // a device is online.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS away (
                account      TEXT PRIMARY KEY,
                away_text    TEXT NOT NULL,
                last_beat_at INTEGER NOT NULL,
                updated_at   INTEGER NOT NULL
            )'
        );
        // Presence (opt-in; see honest-limits): the online/away/idle status a user shares with buddies,
        // refreshed by a heartbeat. The server learns this status continuously, which is the documented
        // relaxation; it is empty for anyone who has not opted in.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS presence (
                account      TEXT PRIMARY KEY,
                status       TEXT NOT NULL,
                last_beat_at INTEGER NOT NULL
            )'
        );
        // Fixed-window rate counter for cross-user key-package claims (one row per caller->target pair),
        // so one account cannot drain a target''s one-time prekeys in a tight loop. Consuming a target''s
        // one-times is a legitimate, tested operation (adding their devices to a group); this only
        // throttles abusive burst rates. See UserStore::allowTake and honest-limits (prekey exhaustion).
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS take_rate (
                caller       TEXT NOT NULL,
                target       TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                count        INTEGER NOT NULL,
                PRIMARY KEY (caller, target)
            )'
        );
        // take_rate rows pair a caller with a target, which is a contact-graph fragment at rest (P2 says
        // the server stores no contact graph). They are only meaningful for the current window, so they
        // are pruned by window_start (UserStore::pruneRateRows); this index keeps that prune cheap.
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_take_rate_window ON take_rate(window_start)');
        // Fixed-window probe counter for cross-user directory reads (lookup / take-keys / away /
        // presence): ONE row per CALLER, deliberately with NO target column, so the throttle itself can
        // never become the contact graph the take_rate table accidentally is. See UserStore::allowProbe.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS probe_rate (
                caller       TEXT PRIMARY KEY,
                window_start INTEGER NOT NULL,
                count        INTEGER NOT NULL
            )'
        );
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_probe_rate_window ON probe_rate(window_start)');
        // Spent proof-of-work challenges, so one solution cannot be replayed into many registrations.
        // Rows are pruned past their expiry; the table only ever holds one window of registrations.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS pow_spent (
                challenge  TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            )'
        );
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_pow_spent_exp ON pow_spent(expires_at)');
        // The server-side secret that MACs a challenge, so the server keeps no per-challenge state.
        // Generated once, on first use.
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS server_secret (id INTEGER PRIMARY KEY, secret TEXT NOT NULL)');
        // ADR-022 P7: signed device revocation records. Each row is an OPAQUE blob signed by the
        // account's authorization key, naming one revoked device signature key. This server is a
        // dead drop for them and nothing more: it holds no account key, so it cannot forge a record,
        // and every client re-verifies every record's signature before honoring it. Withholding rows
        // is the only attack available here, and that costs liveness (a device stays admissible
        // longer), never soundness.
        //
        // The PRIMARY KEY on the record itself makes re-posting idempotent, which matters because the
        // client re-posts on every revoke retry.
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS device_revocations (
                record     TEXT PRIMARY KEY,
                account    TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )'
        );
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_revocations_account ON device_revocations(account)');
        $this->migrateLegacyIdentityKey();
        // AFTER the legacy rebuild, which recreates `users` from a fixed column list and would otherwise
        // drop this column again, 500-ing the request that follows on an old database.
        // The v2 auth verifier: a FAST hash of a secret the client already derived with Argon2id. Nullable
        // because existing accounts carry only the v1 (server-Argon2id) hash until their next sign-in.
        $this->ensureColumn('users', 'auth_v2', 'TEXT');
        // The account's authorization epoch: an EXPLICIT monotonic counter, bumped once per successful
        // device revocation. It used to be derived by counting revoked device rows, which coupled a
        // security floor to a history table: pruning old tombstones silently walked the epoch BACKWARD
        // while every device's local floor stayed where it was (the floor only ever rises), so a newly
        // paired device was certified below the floor and could never join. Backfilled from that count
        // so no account's epoch moves at upgrade time; from here the two are independent.
        $this->ensureColumn('users', 'account_epoch', 'INTEGER NOT NULL DEFAULT 0');
        $this->backfillAccountEpoch();
    }

    /** Seed account_epoch from the historical revoked-row count, ONCE, for accounts still at 0. Skips
     * any account already carrying a value, so it can never lower an epoch that has moved on. */
    private function backfillAccountEpoch(): void
    {
        $this->pdo->exec(
            'UPDATE users SET account_epoch = (
                SELECT COUNT(*) FROM devices d
                WHERE d.account = users.username_hash AND d.revoked_at IS NOT NULL
             ) WHERE account_epoch = 0'
        );
    }

    /** Add a column to a table if it is missing (for upgrading an existing database in place). */
    private function ensureColumn(string $table, string $column, string $type): void
    {
        $info = $this->pdo->query('PRAGMA table_info(' . $table . ')');
        if ($info === false) {
            return;
        }
        $cols = $info->fetchAll();
        $info->closeCursor();
        foreach ($cols as $col) {
            if (is_array($col) && ($col['name'] ?? null) === $column) {
                return; // already present
            }
        }
        $this->pdo->exec('ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $type);
    }

    /**
     * One-time migration from the pre-multi-device schema, where each account had a single
     * identity_key column on users. Backfill each account''s key as its first device, then rebuild
     * users without the column. Idempotent: it no-ops once the column is gone.
     */
    private function migrateLegacyIdentityKey(): void
    {
        $info = $this->pdo->query('PRAGMA table_info(users)');
        if ($info === false) {
            return;
        }
        // Fully consume the cursor before the transaction below: an open statement on this connection
        // would make the DROP TABLE fail with "database table is locked".
        $cols = $info->fetchAll();
        $info->closeCursor();
        $hasIdentityKey = false;
        foreach ($cols as $col) {
            if (is_array($col) && ($col['name'] ?? null) === 'identity_key') {
                $hasIdentityKey = true;
                break;
            }
        }
        if (!$hasIdentityKey) {
            return;
        }
        $this->pdo->beginTransaction();
        $this->pdo->exec(
            "INSERT OR IGNORE INTO devices (device_id, account, device_pub, label, added_at, last_seen_at, revoked_at)
             SELECT lower(hex(randomblob(16))), username_hash, identity_key, NULL, created_at, created_at, NULL
             FROM users WHERE identity_key IS NOT NULL AND identity_key <> ''"
        );
        $this->pdo->exec('CREATE TABLE users_new (username_hash TEXT PRIMARY KEY, auth_hash TEXT NOT NULL, created_at INTEGER NOT NULL)');
        $this->pdo->exec('INSERT INTO users_new (username_hash, auth_hash, created_at) SELECT username_hash, auth_hash, created_at FROM users');
        $this->pdo->exec('DROP TABLE users');
        $this->pdo->exec('ALTER TABLE users_new RENAME TO users');
        $this->pdo->commit();
    }
}
