<?php

declare(strict_types=1);

namespace DeadDrop\ControlPlane\Tests;

use DeadDrop\ControlPlane\Api;
use DeadDrop\ControlPlane\Db;
use DeadDrop\ControlPlane\UserStore;
use PDO;
use PHPUnit\Framework\TestCase;

final class AccountTest extends TestCase
{
    private Api $api;
    private PDO $pdo; // the database behind $this->api, for asserting on rows the API does not expose
    private string $u;
    private string $a;
    private string $k; // the first device key

    protected function setUp(): void
    {
        $this->pdo = (new Db(':memory:'))->pdo();
        $this->api = new Api(new UserStore($this->pdo, 1_000_000, 8)); // real proof of work, low difficulty
        $this->u = str_repeat('a', 64);
        $this->a = str_repeat('b', 64);
        $this->k = str_repeat('c', 64);
    }

    /** COUNT(*) for a parameterized query against the API's own database. */
    private function countRows(string $sql, string ...$params): int
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return (int) $stmt->fetchColumn();
    }

    /** @param array<array-key, mixed> $body */
    private function register(array $body): int
    {
        // Every registration carries its own freshly solved proof: challenges are single-use, so reusing
        // one here would (correctly) be refused as a replay.
        return $this->api->register([...$body, 'pow' => $this->pow()])[0];
    }

    /** Solve a registration challenge the way the client does: grind a nonce until the digest has the
     *  required leading zero bits. The suite runs at a low difficulty so this is milliseconds, but it is
     *  the SAME code path a real registration takes, MAC and replay guard included. */
    /** @return array{challenge: string, expiresAt: mixed, mac: mixed, nonce: string} */
    private function pow(): array
    {
        $c = $this->api->challenge();
        self::assertSame(200, $c[0]);
        $challenge = $c[1]['challenge'];
        self::assertIsString($challenge);
        $bits = $c[1]['bits'];
        self::assertIsInt($bits);
        for ($n = 0; ; $n++) {
            $digest = hash('sha256', $challenge . "\x1f" . $n);
            $lead = 0;
            foreach (str_split($digest) as $ch) {
                $v = (int) hexdec($ch);
                if ($v === 0) {
                    $lead += 4;
                    continue;
                }
                $lead += $v >= 8 ? 0 : ($v >= 4 ? 1 : ($v >= 2 ? 2 : 3));
                break;
            }
            if ($lead >= $bits) {
                return ['challenge' => $challenge, 'expiresAt' => $c[1]['expiresAt'], 'mac' => $c[1]['mac'], 'nonce' => (string) $n];
            }
        }
    }

    private function registerToken(): string
    {
        $res = $this->api->register(['usernameHash' => $this->u, 'authSecret' => $this->a, 'identityKey' => $this->k, 'pow' => $this->pow()]);
        self::assertSame(201, $res[0]);
        self::assertIsString($res[1]['token']);
        return $res[1]['token'];
    }

    private function loginToken(): string
    {
        $res = $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a]);
        self::assertSame(200, $res[0]);
        self::assertIsString($res[1]['token']);
        return $res[1]['token'];
    }

    /**
     * The caller''s device list, narrowed for static analysis.
     *
     * @return list<array<array-key, mixed>>
     */
    private function devicesOf(string $token): array
    {
        $res = $this->api->listDevices(['token' => $token]);
        self::assertSame(200, $res[0]);
        $devices = $res[1]['devices'];
        self::assertIsArray($devices);
        $out = [];
        foreach ($devices as $d) {
            self::assertIsArray($d);
            $out[] = $d;
        }
        return $out;
    }

    /** Register and log in a second account, returning a live session token for directory reads. */
    private function otherToken(): string
    {
        $u2 = str_repeat('e', 64);
        $a2 = str_repeat('f', 64);
        $this->api->register(['usernameHash' => $u2, 'authSecret' => $a2, 'identityKey' => str_repeat('7', 64), 'pow' => $this->pow()]);
        $t = $this->api->login(['usernameHash' => $u2, 'authSecret' => $a2])[1]['token'];
        self::assertIsString($t);
        return $t;
    }

    /**
     * The single current-device row in a list.
     *
     * @param list<array<array-key, mixed>> $devices
     * @return array<array-key, mixed>
     */
    private static function currentOf(array $devices): array
    {
        $current = array_values(array_filter($devices, static fn (array $d): bool => ($d['current'] ?? null) === true));
        self::assertCount(1, $current);
        return $current[0];
    }

    public function testRegisterCreatesAccountAndFirstDeviceThenRejectsDuplicate(): void
    {
        $token = $this->registerToken();
        // The account starts with exactly one device.
        self::assertCount(1, $this->devicesOf($token));
        // A second registration for the same username is denied even with a different device key.
        self::assertSame(409, $this->register(['usernameHash' => $this->u, 'authSecret' => str_repeat('d', 64), 'identityKey' => str_repeat('e', 64)]));
    }

    public function testRegisterRejectsMalformedInput(): void
    {
        self::assertSame(400, $this->register(['usernameHash' => 'nothex', 'authSecret' => $this->a, 'identityKey' => $this->k]));
        self::assertSame(400, $this->register(['authSecret' => $this->a, 'identityKey' => $this->k]));
    }

    public function testLoginVerifiesTheCredential(): void
    {
        $this->registerToken();
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a])[0]);
        self::assertSame(401, $this->api->login(['usernameHash' => $this->u, 'authSecret' => str_repeat('d', 64)])[0]);
        self::assertSame(401, $this->api->login(['usernameHash' => str_repeat('f', 64), 'authSecret' => $this->a])[0]);
    }

    public function testLoginUpgradesAHashStoredUnderWeakerParametersAndKeepsAuthenticating(): void
    {
        $this->registerToken();
        // A row written by an older deployment at a lower cost. It must keep verifying (password_verify
        // reads the parameters out of the hash) and must be rewritten at the pinned cost on first use,
        // so the stored corpus converges on one parameter set - which is what keeps the real and dummy
        // login paths at identical cost, and therefore keeps login from timing out account existence.
        $weak = password_hash($this->a, PASSWORD_ARGON2ID, ['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]);
        $this->pdo->prepare('UPDATE users SET auth_hash = ? WHERE username_hash = ?')->execute([$weak, $this->u]);

        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a])[0]);

        $stmt = $this->pdo->prepare('SELECT auth_hash FROM users WHERE username_hash = ?');
        $stmt->execute([$this->u]);
        $stored = $stmt->fetchColumn();
        self::assertIsString($stored);
        self::assertNotSame($weak, $stored, 'the weak hash was rehashed on successful login');
        self::assertStringContainsString('m=65536,t=4,p=1', $stored, 'rehashed at the pinned parameters');
        // The upgraded row still accepts the right secret and still rejects a wrong one.
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a])[0]);
        self::assertSame(401, $this->api->login(['usernameHash' => $this->u, 'authSecret' => str_repeat('d', 64)])[0]);
    }

    public function testLookupReturnsTheActiveDeviceKeyForAuthenticatedSessions(): void
    {
        $token = $this->registerToken();
        $ok = $this->api->lookup(['token' => $token, 'usernameHash' => $this->u]);
        self::assertSame(200, $ok[0]);
        self::assertSame($this->k, $ok[1]['activeDeviceKey']);
        self::assertSame([$this->k], $ok[1]['deviceKeys']);

        self::assertSame(401, $this->api->lookup(['usernameHash' => $this->u])[0]); // no token
    }

    public function testLookupAnswersUnknownAndDevicelessAccountsWithTheSameEmptyShape(): void
    {
        // The old 404-vs-200 split made this the cheapest existence oracle in the system. Now every
        // miss is one 200 with an empty device list, whatever the reason for the miss.
        $token = $this->registerToken();
        $miss = [200, ['activeDeviceKey' => null, 'deviceKeys' => []]];

        // (a) no such account.
        self::assertSame($miss, $this->api->lookup(['token' => $token, 'usernameHash' => str_repeat('f', 64)]));

        // (b) the account exists but every device of it is revoked: byte-identical to (a).
        $deviceId = self::currentOf($this->devicesOf($token))['deviceId'];
        self::assertIsString($deviceId);
        self::assertSame(200, $this->api->revokeDevice(['token' => $token, 'deviceId' => $deviceId])[0]);
        $other = $this->otherToken();
        self::assertSame($miss, $this->api->lookup(['token' => $other, 'usernameHash' => $this->u]));

        // A malformed hash is still a 400: that is about the caller's own request, not about a target.
        self::assertSame(400, $this->api->lookup(['token' => $other, 'usernameHash' => 'nothex'])[0]);
    }

    public function testProbeThrottleAllowsALegitimateRateThenDeniesAndRollsWithTheWindow(): void
    {
        $pdo = (new Db(':memory:'))->pdo();
        $store = new UserStore($pdo, 1_000_000); // window start: 1_000_000 % 60 == 40, so the window is [999_960, 1_000_020)
        $caller = $this->u;

        // Read the ceiling from the constant rather than hardcoding it: an earlier cut sized this at 120,
        // which was BELOW what the client's own 30-second presence poll spends, so real users' buddies
        // silently read offline. A test that pins the number would have shipped that quietly again.
        $cap = (new \ReflectionClass(UserStore::class))->getConstant('PROBE_MAX_PER_WINDOW');
        self::assertIsInt($cap);
        for ($i = 0; $i < $cap; $i++) {
            self::assertTrue($store->allowProbe($caller), "probe $i is within the budget");
        }
        self::assertFalse($store->allowProbe($caller), 'the probe past the ceiling is denied');
        self::assertFalse($store->allowProbe($caller), 'and it stays denied for the rest of the window');

        // The budget is per caller, so a different account is unaffected.
        self::assertTrue($store->allowProbe(str_repeat('9', 64)));

        // The next window gives the caller a fresh budget.
        self::assertTrue((new UserStore($pdo, 1_000_060))->allowProbe($caller));
    }

    public function testProbeThrottleFailsClosedWhenTheCounterCannotBeRead(): void
    {
        // A database fault that silently disabled the limiter is exactly the window a harvester wants,
        // so an unreadable counter must DENY. Dropping the table is the bluntest way to make the read
        // fail; a locked or corrupt database is the realistic one.
        $pdo = (new Db(':memory:'))->pdo();
        $store = new UserStore($pdo, 1_000_000);
        self::assertTrue($store->allowProbe($this->u));
        $pdo->exec('DROP TABLE probe_rate');
        self::assertFalse($store->allowProbe($this->u), 'no counter, no probe');
    }

    public function testProbeBudgetIsSharedAcrossTheDirectoryEndpointsAndDenialLooksLikeAMiss(): void
    {
        // One shared budget: an attacker must not get a full budget of lookups AND another of presence
        // polls AND another of away reads. Spend it all on lookup, then check the other three endpoints
        // answer exactly as they would for an account that does not exist.
        $token = $this->registerToken();
        $this->api->publishKeys(['token' => $token, 'keyPackages' => [
            ['keyPackage' => str_repeat('cc', 100), 'ref' => str_repeat('9', 64), 'lastResort' => true],
        ]]);
        self::assertSame(200, $this->api->setPresence(['token' => $token, 'status' => 'online'])[0]);

        $other = $this->otherToken();
        $unknown = str_repeat('f', 64);
        // What a miss looks like for each endpoint, captured while the caller still has budget.
        $lookupMiss = $this->api->lookup(['token' => $other, 'usernameHash' => $unknown]);
        $awayMiss = $this->api->awayLookup(['token' => $other, 'usernameHash' => $unknown]);
        $presenceMiss = $this->api->getPresence(['token' => $other, 'usernameHash' => $unknown]);
        $takeMiss = $this->api->takeKeys(['token' => $other, 'usernameHash' => $unknown]);

        // Burn the rest of the shared budget (4 probes are already spent above). Sized off the constant
        // so raising the ceiling cannot silently stop this test from reaching it.
        $cap = (new \ReflectionClass(UserStore::class))->getConstant('PROBE_MAX_PER_WINDOW');
        self::assertIsInt($cap);
        for ($i = 0; $i < $cap - 4; $i++) {
            $this->api->lookup(['token' => $other, 'usernameHash' => $unknown]);
        }

        // The target is real, live and has key packages - and every endpoint now answers as a miss.
        self::assertSame($lookupMiss, $this->api->lookup(['token' => $other, 'usernameHash' => $this->u]));
        self::assertSame($awayMiss, $this->api->awayLookup(['token' => $other, 'usernameHash' => $this->u]));
        self::assertSame($presenceMiss, $this->api->getPresence(['token' => $other, 'usernameHash' => $this->u]));
        self::assertSame($takeMiss, $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u]));
        // Specifically: no 429, no distinct error body, nothing that says "you were throttled".
        self::assertSame(200, $this->api->lookup(['token' => $other, 'usernameHash' => $this->u])[0]);
        self::assertSame('offline', $this->api->getPresence(['token' => $other, 'usernameHash' => $this->u])[1]['status']);

        // The throttled caller's own account is untouched: self-scoped writes are not directory probes.
        self::assertSame(200, $this->api->setPresence(['token' => $other, 'status' => 'online'])[0]);
        // A different caller reads the truth, proving the throttle is per caller and not a server-wide
        // outage (and that the target really was live all along).
        $fresh = $this->api->lookup(['token' => $token, 'usernameHash' => $this->u]);
        self::assertSame($this->k, $fresh[1]['activeDeviceKey']);
    }

    public function testDeleteAccountAlsoErasesTheRateCounterRows(): void
    {
        // take_rate rows pair a caller with a target: a contact-graph fragment the server is not
        // supposed to hold (P2). Self destruct must not leave them behind.
        $token = $this->registerToken();
        $other = $this->otherToken();
        $u2 = str_repeat('e', 64); // the account behind otherToken()
        // One row each way: (u2 -> u) and (u -> u2).
        self::assertSame(200, $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u])[0]);
        self::assertSame(200, $this->api->takeKeys(['token' => $token, 'usernameHash' => $u2])[0]);
        self::assertSame(2, $this->countRows('SELECT COUNT(*) FROM take_rate'));
        self::assertSame(1, $this->countRows('SELECT COUNT(*) FROM probe_rate WHERE caller = ?', $u2));

        self::assertSame(200, $this->api->deleteAccount(['token' => $other])[0]);
        self::assertSame(0, $this->countRows('SELECT COUNT(*) FROM probe_rate WHERE caller = ?', $u2));
        // Both rows are gone: the one where the deleted account was the CALLER and the one where it was
        // the TARGET. Either alone would still say this account and that account had contact.
        self::assertSame(0, $this->countRows('SELECT COUNT(*) FROM take_rate'));
    }

    public function testStaleRateRowsArePrunedWhenACallerRollsIntoANewWindow(): void
    {
        // The (caller, target) residue in take_rate must not accumulate forever.
        $pdo = (new Db(':memory:'))->pdo();
        (new UserStore($pdo, 1_000_000))->allowTake($this->u, str_repeat('7', 64));
        $count = static function () use ($pdo): int {
            $stmt = $pdo->prepare('SELECT COUNT(*) FROM take_rate');
            $stmt->execute();
            return (int) $stmt->fetchColumn();
        };
        self::assertSame(1, $count());

        // A probe three windows later prunes it (and any probe row older than the previous window).
        self::assertTrue((new UserStore($pdo, 1_000_180))->allowProbe($this->u));
        self::assertSame(0, $count());
    }

    public function testAddDeviceIsTwoFactorAndIdempotent(): void
    {
        $this->registerToken();
        $token2 = $this->loginToken(); // a second device signs in (unbound session)
        $k2 = str_repeat('2', 64);

        self::assertSame(401, $this->api->addDevice(['authSecret' => $this->a, 'deviceKey' => $k2])[0]); // no token
        self::assertSame(401, $this->api->addDevice(['token' => $token2, 'authSecret' => str_repeat('9', 64), 'deviceKey' => $k2])[0]); // wrong passphrase

        $add = $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2]);
        self::assertSame(201, $add[0]);
        self::assertIsString($add[1]['deviceId']);
        // Idempotent: re-enrolling the same key is a 200, not a duplicate.
        self::assertSame(200, $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2])[0]);

        // Now the account has two devices and the directory lists both.
        $keys = $this->api->lookup(['token' => $token2, 'usernameHash' => $this->u])[1]['deviceKeys'];
        self::assertIsArray($keys);
        self::assertCount(2, $keys);
    }

    public function testADeviceKeyClaimedByAnotherAccountIsRejected(): void
    {
        $this->registerToken(); // account 1 owns $this->k
        // account 2 registers, then tries to enroll account 1's device key.
        $u2 = str_repeat('e', 64);
        $a2 = str_repeat('f', 64);
        $this->api->register(['usernameHash' => $u2, 'authSecret' => $a2, 'identityKey' => str_repeat('7', 64), 'pow' => $this->pow()]);
        $token2 = $this->api->login(['usernameHash' => $u2, 'authSecret' => $a2])[1]['token'];
        self::assertIsString($token2);
        $taken = $this->api->addDevice(['token' => $token2, 'authSecret' => $a2, 'deviceKey' => $this->k]);
        self::assertSame(409, $taken[0]);
        self::assertSame('device_key_taken', $taken[1]['error']);
    }

    public function testListDevicesMarksTheCurrentDevice(): void
    {
        $token1 = $this->registerToken(); // bound to device 1
        $token2 = $this->loginToken();
        $k2 = str_repeat('2', 64);
        $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2]); // binds token2 -> device 2

        // Each session sees exactly one current device, and it is its own.
        self::assertSame($this->k, self::currentOf($this->devicesOf($token1))['deviceKey']);
        self::assertSame($k2, self::currentOf($this->devicesOf($token2))['deviceKey']);
    }

    public function testAccountEpochIsAnExplicitMonotonicCounterNotACountOfTombstones(): void
    {
        // The whole point of the counter. The epoch used to BE the number of revoked device rows, so
        // pruning old tombstones walked it backward while each device's local floor stayed put, and the
        // next paired device was certified below the floor and could never join. The counter is now
        // authoritative: revoking raises it, and deleting history does not lower it.
        $token1 = $this->registerToken();
        self::assertSame(0, $this->api->listDevices(['token' => $token1])[1]['accountEpoch']);

        $k2 = str_repeat('2', 64);
        $token2 = $this->loginToken();
        $deviceId2 = $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2])[1]['deviceId'];
        self::assertIsString($deviceId2);
        // Enrolling a device does NOT move the epoch; only revocation does.
        self::assertSame(0, $this->api->listDevices(['token' => $token1])[1]['accountEpoch']);

        self::assertSame(200, $this->api->revokeDevice(['token' => $token1, 'deviceId' => $deviceId2])[0]);
        self::assertSame(1, $this->api->listDevices(['token' => $token1])[1]['accountEpoch']);

        // Re-revoking the SAME device is idempotent and must not inflate the floor.
        $this->api->revokeDevice(['token' => $token1, 'deviceId' => $deviceId2]);
        self::assertSame(1, $this->api->listDevices(['token' => $token1])[1]['accountEpoch']);

        // Prune the tombstone, exactly as an operator cleaning up device history would.
        $this->pdo->prepare('DELETE FROM devices WHERE device_id = ?')->execute([$deviceId2]);
        self::assertSame(
            1,
            $this->api->listDevices(['token' => $token1])[1]['accountEpoch'],
            'deleting revoked history must NEVER lower the authorization floor',
        );
    }

    public function testRevokeBurnsTheDeviceCutsItsSessionAndFallsBackTheDirectory(): void
    {
        $token1 = $this->registerToken();
        $token2 = $this->loginToken();
        $k2 = str_repeat('2', 64);
        $deviceId2 = $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2])[1]['deviceId'];
        self::assertIsString($deviceId2);

        // device 2 is now the most-recently-seen, so it is the active receiver.
        self::assertSame($k2, $this->api->lookup(['token' => $token1, 'usernameHash' => $this->u])[1]['activeDeviceKey']);

        // Revoke device 2 from device 1.
        self::assertSame(200, $this->api->revokeDevice(['token' => $token1, 'deviceId' => $deviceId2])[0]);
        // device 2's session is cut immediately.
        self::assertSame(401, $this->api->listDevices(['token' => $token2])[0]);
        // The directory falls back to the remaining active device.
        $look = $this->api->lookup(['token' => $token1, 'usernameHash' => $this->u]);
        self::assertSame($this->k, $look[1]['activeDeviceKey']);
        self::assertSame([$this->k], $look[1]['deviceKeys']);
        // The revoked key stays burned: it cannot be re-enrolled.
        $token3 = $this->loginToken();
        $reuse = $this->api->addDevice(['token' => $token3, 'authSecret' => $this->a, 'deviceKey' => $k2]);
        self::assertSame(409, $reuse[0]);
        self::assertSame('device_revoked', $reuse[1]['error']);
    }

    public function testDeleteAccountErasesEverythingAndFreesTheUsername(): void
    {
        $token1 = $this->registerToken();
        $token2 = $this->loginToken();
        $k2 = str_repeat('2', 64);
        $deviceId2 = $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2])[1]['deviceId'];
        self::assertIsString($deviceId2);

        // Self destruct needs a session: no token is unauthorized.
        self::assertSame(401, $this->api->deleteAccount([])[0]);

        // Delete the whole account from device 1.
        self::assertSame(200, $this->api->deleteAccount(['token' => $token1])[0]);

        // Every session is dead (both devices), and the account no longer authenticates.
        self::assertSame(401, $this->api->listDevices(['token' => $token1])[0]);
        self::assertSame(401, $this->api->listDevices(['token' => $token2])[0]);
        self::assertSame(401, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a])[0]);

        // The username is free again: it registers fresh, proving the old account, devices, and keys are gone.
        self::assertSame(201, $this->register(['usernameHash' => $this->u, 'authSecret' => str_repeat('e', 64), 'identityKey' => str_repeat('9', 64)]));
    }

    public function testSessionBoundToARevokedDeviceReadsDeadWhileUnboundLoginSurvives(): void
    {
        // Defence in depth for the bind-races-revoke TOCTOU: revokeDevice already deletes the device's
        // sessions, but a session bound to a device that is later revoked (without its row being deleted)
        // must still read as dead. A fresh UNBOUND login on the account must keep working.
        $pdo = (new Db(':memory:'))->pdo();
        $store = new UserStore($pdo, 1000);
        $store->register($this->u, $this->a, $this->k);
        [$status, $deviceId2] = $store->upsertDevice($this->u, str_repeat('2', 64));
        self::assertSame('created', $status);
        self::assertIsString($deviceId2);

        $bound = $store->createSession($this->u, $deviceId2); // a session bound to device 2
        $unbound = $store->createSession($this->u); // a fresh, still-unbound login
        self::assertNotNull($store->sessionContext($bound));
        self::assertNotNull($store->sessionContext($unbound));

        // Revoke device 2's row directly (revokeDevice would also delete the session; this simulates the
        // race where a bind lands just after the revoke's session-DELETE).
        $pdo->prepare('UPDATE devices SET revoked_at = 1 WHERE device_id = ?')->execute([$deviceId2]);

        self::assertNull($store->sessionContext($bound)); // the burned-device session is now dead
        self::assertNotNull($store->sessionContext($unbound)); // the unbound login is unaffected
    }

    public function testRevokeUnknownDeviceIs404AndAccountScoped(): void
    {
        $token = $this->registerToken();
        self::assertSame(404, $this->api->revokeDevice(['token' => $token, 'deviceId' => str_repeat('0', 32)])[0]);
        self::assertSame(400, $this->api->revokeDevice(['token' => $token, 'deviceId' => 'nothex'])[0]);
        self::assertSame(401, $this->api->revokeDevice(['deviceId' => str_repeat('0', 32)])[0]);
    }

    public function testActiveDeviceFollowsTheMostRecentlySeenAtTheStoreLevel(): void
    {
        // Two stores over one db with different clocks, so last_seen_at differs deterministically.
        $pdo = (new Db(':memory:'))->pdo();
        $early = new UserStore($pdo, 1000);
        $early->register($this->u, $this->a, $this->k); // device 1 seen at t=1000
        $k2 = str_repeat('2', 64);
        $late = new UserStore($pdo, 2000);
        $late->upsertDevice($this->u, $k2); // device 2 seen at t=2000 -> most recent
        $active = $late->lookupActive($this->u);
        self::assertNotNull($active);
        self::assertSame($k2, $active['activeDeviceKey']);
        // device 1 re-enrolls at t=3000 and reclaims active.
        $latest = new UserStore($pdo, 3000);
        $latest->upsertDevice($this->u, $this->k);
        self::assertSame($this->k, $latest->lookupActive($this->u)['activeDeviceKey'] ?? null);
    }

    public function testLegacyIdentityKeySchemaMigratesToDevices(): void
    {
        // Build the pre-multi-device schema with one account, then open it with the new Db.
        $file = tempnam(sys_get_temp_dir(), 'ddleg') . '.db';
        $legacy = new PDO('sqlite:' . $file);
        $legacy->exec('CREATE TABLE users (username_hash TEXT PRIMARY KEY, auth_hash TEXT NOT NULL, identity_key TEXT NOT NULL, created_at INTEGER NOT NULL)');
        $legacy->exec('CREATE TABLE sessions (token TEXT PRIMARY KEY, username_hash TEXT NOT NULL, expires_at INTEGER NOT NULL)');
        $legacy->exec("INSERT INTO users VALUES ('" . $this->u . "', 'hash', '" . $this->k . "', 500)");
        unset($legacy);

        $pdo = (new Db($file))->pdo(); // runs the migration
        $store = new UserStore($pdo, 9000);
        // The old identity key became the account's first device.
        $active = $store->lookupActive($this->u);
        self::assertNotNull($active);
        self::assertSame($this->k, $active['activeDeviceKey']);
        // The pre-multi-device sessions table gained device_id, so a device-bound session still works.
        $token = $store->createSession($this->u, 'devicexyz');
        self::assertSame($this->u, $store->sessionUser($token));
        // users no longer carries identity_key.
        $info = $pdo->query('PRAGMA table_info(users)');
        self::assertNotFalse($info);
        $names = [];
        foreach ($info as $c) {
            $names[] = is_array($c) ? ($c['name'] ?? null) : null;
        }
        self::assertNotContains('identity_key', $names);
        @unlink($file);
    }

    public function testPublishKeysRequiresAnEnrolledDevice(): void
    {
        $kps = [['keyPackage' => str_repeat('aa', 100), 'ref' => str_repeat('1', 64), 'lastResort' => false]];
        $token1 = $this->registerToken(); // register binds the session to device 1
        self::assertSame(201, $this->api->publishKeys(['token' => $token1, 'keyPackages' => $kps])[0]);

        $unbound = $this->loginToken(); // a plain login session is not yet bound to a device
        self::assertSame(409, $this->api->publishKeys(['token' => $unbound, 'keyPackages' => $kps])[0]);
        self::assertSame(401, $this->api->publishKeys(['keyPackages' => $kps])[0]);
        self::assertSame(400, $this->api->publishKeys(['token' => $token1, 'keyPackages' => []])[0]);
        self::assertSame(400, $this->api->publishKeys(['token' => $token1, 'keyPackages' => [['keyPackage' => 'NOThex', 'ref' => str_repeat('1', 64), 'lastResort' => false]]])[0]);
    }

    public function testListDevicesFlagsAuthorizedOnlyForDevicesThatPublishedKeyPackages(): void
    {
        $token1 = $this->registerToken(); // device 1, bound to token1
        // A freshly registered device has published no key packages yet: not authorized.
        self::assertFalse(self::currentOf($this->devicesOf($token1))['authorized']);

        // Enroll device 2 (bound to token2) but never publish its keys: an unauthorized orphan.
        $token2 = $this->loginToken();
        $k2 = str_repeat('2', 64);
        $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2]);

        // Device 1 publishes a one-time key package: it becomes authorized.
        self::assertSame(201, $this->api->publishKeys(['token' => $token1, 'keyPackages' => [
            ['keyPackage' => str_repeat('aa', 100), 'ref' => str_repeat('1', 64), 'lastResort' => false],
        ]])[0]);
        $byKey = [];
        foreach ($this->devicesOf($token1) as $d) {
            self::assertIsString($d['deviceKey']);
            $byKey[$d['deviceKey']] = $d;
        }
        self::assertTrue($byKey[$this->k]['authorized'], 'device 1 published a key package');
        self::assertFalse($byKey[$k2]['authorized'], 'device 2 never published: an unauthorized orphan');

        // A device whose ONLY package is the reusable last-resort still counts authorized.
        self::assertSame(201, $this->api->publishKeys(['token' => $token2, 'keyPackages' => [
            ['keyPackage' => str_repeat('bb', 100), 'ref' => str_repeat('2', 64), 'lastResort' => true],
        ]])[0]);
        $byKey2 = [];
        foreach ($this->devicesOf($token1) as $d) {
            self::assertIsString($d['deviceKey']);
            $byKey2[$d['deviceKey']] = $d;
        }
        self::assertTrue($byKey2[$k2]['authorized'], 'a last-resort-only device is still authorized');
    }

    public function testReapDeletesAgedOrphansOnlyAndPreservesTombstonesRevokedCountAndSessions(): void
    {
        $pdo = (new Db(':memory:'))->pdo();
        $early = new UserStore($pdo, 1000);
        $d1 = $early->register($this->u, $this->a, $this->k); // device 1, seen at t=1000
        self::assertIsString($d1);
        $early->publishKeyPackages($this->u, $d1, [['blob' => 'aa', 'ref' => str_repeat('1', 64), 'lastResort' => false]]); // authorized

        [, $d2] = $early->upsertDevice($this->u, str_repeat('2', 64)); // device 2: an orphan (never publishes)
        $orphanSession = $early->createSession($this->u, $d2);
        self::assertNotNull($early->sessionContext($orphanSession));

        [, $d4] = $early->upsertDevice($this->u, str_repeat('4', 64));
        self::assertIsString($d4);
        $early->revokeDevice($this->u, $d4); // device 4: a revoked tombstone
        $revokedBefore = count(array_filter($early->listDevices($this->u), static fn ($d) => $d['revoked']));

        // Sweep past the 600s grace.
        $late = new UserStore($pdo, 1000 + 601);
        self::assertSame(1, $late->reapOrphanDevices($this->u), 'only the aged orphan device 2 is reaped');

        $keys = [];
        foreach ($late->listDevices($this->u) as $d) {
            $keys[$d['deviceKey']] = $d;
        }
        self::assertArrayHasKey($this->k, $keys, 'the authorized device survives');
        self::assertArrayNotHasKey(str_repeat('2', 64), $keys, 'the aged orphan is reaped');
        self::assertArrayHasKey(str_repeat('4', 64), $keys, 'the revoked tombstone survives (P6 epoch floor)');
        self::assertTrue($keys[str_repeat('4', 64)]['revoked']);
        self::assertNull($late->sessionContext($orphanSession), 'the reaped orphan session is dead');
        $revokedAfter = count(array_filter($late->listDevices($this->u), static fn ($d) => $d['revoked']));
        self::assertSame($revokedBefore, $revokedAfter, 'the revoked-row count is invariant');
    }

    public function testReapSparesFreshOrphansAndAReapedKeyReenrollsAsCreated(): void
    {
        $pdo = (new Db(':memory:'))->pdo();
        $early = new UserStore($pdo, 1000);
        $d1 = $early->register($this->u, $this->a, $this->k);
        self::assertIsString($d1);
        $early->publishKeyPackages($this->u, $d1, [['blob' => 'aa', 'ref' => str_repeat('1', 64), 'lastResort' => false]]); // authorized, spared
        $early->upsertDevice($this->u, str_repeat('2', 64)); // orphan enrolled at t=1000

        // Only 100s later (< 600 grace): the fresh orphan survives.
        self::assertSame(0, (new UserStore($pdo, 1100))->reapOrphanDevices($this->u));

        // Past the grace: reaped, and its key re-enrolls as 'created' (NOT the burned-key 409).
        $late = new UserStore($pdo, 1000 + 601);
        self::assertSame(1, $late->reapOrphanDevices($this->u));
        [$status] = $late->upsertDevice($this->u, str_repeat('2', 64));
        self::assertSame('created', $status, 'a reaped innocent key must re-enroll, never hit device_revoked');
    }

    public function testLoginReapsAgedOrphansViaTheApi(): void
    {
        $pdo = (new Db(':memory:'))->pdo();
        $earlyStore = new UserStore($pdo, 1000, 8);
        $early = new Api($earlyStore);
        $ch = $early->challenge()[1];
        $powNonce = 0;
        while (true) {
            $chal = $ch['challenge'];
            self::assertIsString($chal);
            $d = hash('sha256', $chal . "\x1f" . $powNonce);
            $lead = 0;
            foreach (str_split($d) as $c2) {
                $v = (int) hexdec($c2);
                if ($v === 0) {
                    $lead += 4;
                    continue;
                }
                $lead += $v >= 8 ? 0 : ($v >= 4 ? 1 : ($v >= 2 ? 2 : 3));
                break;
            }
            if ($lead >= 8) {
                break;
            }
            $powNonce++;
        }
        $reg = $early->register(['usernameHash' => $this->u, 'authSecret' => $this->a, 'identityKey' => $this->k,
            'pow' => ['challenge' => $ch['challenge'], 'expiresAt' => $ch['expiresAt'], 'mac' => $ch['mac'], 'nonce' => (string) $powNonce]]);
        $early->publishKeys(['token' => $reg[1]['token'], 'keyPackages' => [
            ['keyPackage' => str_repeat('aa', 100), 'ref' => str_repeat('1', 64), 'lastResort' => false],
        ]]); // device 1 authorized
        (new UserStore($pdo, 1000))->upsertDevice($this->u, str_repeat('2', 64)); // orphan at t=1000

        // A login past the grace sweeps the aged orphan.
        (new Api(new UserStore($pdo, 1000 + 601)))->login(['usernameHash' => $this->u, 'authSecret' => $this->a]);

        $keys = array_column((new UserStore($pdo, 1000 + 601))->listDevices($this->u), 'deviceKey');
        self::assertContains($this->k, $keys, 'the authorized device survives');
        self::assertNotContains(str_repeat('2', 64), $keys, 'the aged orphan was reaped on login');
    }

    public function testTakeKeysConsumesOneTimeThenFallsBackToLastResort(): void
    {
        $token1 = $this->registerToken();
        $this->api->publishKeys(['token' => $token1, 'keyPackages' => [
            ['keyPackage' => str_repeat('aa', 100), 'ref' => str_repeat('1', 64), 'lastResort' => false],
            ['keyPackage' => str_repeat('bb', 100), 'ref' => str_repeat('2', 64), 'lastResort' => false],
            ['keyPackage' => str_repeat('cc', 100), 'ref' => str_repeat('3', 64), 'lastResort' => true],
        ]]);
        $other = $this->otherToken();

        $seen = [];
        foreach ([1, 2] as $_) {
            $res = $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u]);
            self::assertSame(200, $res[0]);
            $devices = $res[1]['devices'];
            self::assertIsArray($devices);
            self::assertCount(1, $devices); // one entry per active device
            $d = $devices[0];
            self::assertIsArray($d);
            self::assertSame($this->k, $d['deviceKey']);
            self::assertFalse($d['lastResort']); // one-time packages are claimed first
            self::assertIsString($d['keyPackage']);
            $seen[] = $d['keyPackage'];
        }
        self::assertCount(2, array_unique($seen)); // two distinct one-time packages, each consumed once

        // One-time packages exhausted: fall back to the reusable last-resort, flagged.
        $third = $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u])[1]['devices'];
        self::assertIsArray($third);
        self::assertIsArray($third[0]);
        self::assertTrue($third[0]['lastResort']);
        self::assertSame(str_repeat('cc', 100), $third[0]['keyPackage']);
    }

    public function testTakeKeysThrottlesAtightDrainLoop(): void
    {
        $token1 = $this->registerToken();
        $this->api->publishKeys(['token' => $token1, 'keyPackages' => [
            ['keyPackage' => str_repeat('cc', 100), 'ref' => str_repeat('9', 64), 'lastResort' => true],
        ]]);
        $other = $this->otherToken();
        // A single caller may claim against one target up to the per-window ceiling (30), bounding a
        // prekey-exhaustion drain loop. The very next claim is refused AS A MISS, not with a 429: an
        // explicit rate-limit status here would have told the caller that the separate per-caller probe
        // budget was still available, which is a statistics-free read of throttle state from the one
        // endpoint that must not give one.
        for ($i = 0; $i < 30; $i++) {
            self::assertSame(200, $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u])[0]);
        }
        $refused = $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u]);
        self::assertSame(200, $refused[0]);
        self::assertSame(['devices' => []], $refused[1]);
        // And it is byte-identical to asking for an account that does not exist.
        $missing = $this->api->takeKeys(['token' => $other, 'usernameHash' => str_repeat('7', 64)]);
        self::assertSame($missing, $refused);
    }

    public function testAV2LoginCostsNoServerArgon2AndMigratesOnFirstV1SignIn(): void
    {
        $v2 = str_repeat('5', 64);
        // An account created BEFORE the migration: v1 only, so the server holds an Argon2id hash.
        $this->registerToken();
        $q1 = $this->pdo->prepare('SELECT auth_v2 FROM users WHERE username_hash = ?');
        $q1->execute([$this->u]);
        $row = $q1->fetch();
        self::assertNull(is_array($row) ? $row['auth_v2'] : 'missing', 'a legacy account starts with no v2 verifier');

        // Its first sign-in supplying a v2 secret verifies via v1 and UPGRADES the row.
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a, 'authSecretV2' => $v2])[0]);
        $q2 = $this->pdo->prepare('SELECT auth_v2 FROM users WHERE username_hash = ?');
        $q2->execute([$this->u]);
        $after = $q2->fetch();
        self::assertIsString(is_array($after) ? $after['auth_v2'] : null, 'the account migrated to the fast verifier');

        // From here the v2 secret takes the fast path.
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a, 'authSecretV2' => $v2])[0]);
        // A wrong v2 beside a CORRECT v1 still authenticates, by design: the caller proved knowledge of
        // the passphrase, and a stale or broken client KDF must not lock them out.
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a, 'authSecretV2' => str_repeat('6', 64)])[0]);
        // ...and that must NOT have replaced the stored verifier with the wrong one. If it had, the
        // wrong v2 would then authenticate on the fast path with no passphrase knowledge at all.
        self::assertSame(401, $this->api->login(['usernameHash' => $this->u, 'authSecret' => str_repeat('7', 64), 'authSecretV2' => str_repeat('6', 64)])[0]);
        // The original correct v2 still works, proving the verifier survived intact.
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => str_repeat('7', 64), 'authSecretV2' => $v2])[0]);
        // The v1 secret STILL works on its own after migration, and that is deliberate. /api/add-device
        // authenticates with the v1 secret, and a client whose wasm fails to load has only v1; making the
        // fast verifier exclusive locked every account out of both. v2 is a fast path, not a gate.
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a])[0]);
        // A wrong v1 secret is still refused, so the fallback is a fallback and not a bypass.
        self::assertSame(401, $this->api->login(['usernameHash' => $this->u, 'authSecret' => str_repeat('7', 64)])[0]);
    }

    public function testAddDeviceStillWorksAfterAnAccountMigratesToTheFastVerifier(): void
    {
        // The regression that would have bricked every account: add-device authenticates with the v1
        // secret alone, and the app refuses a sign-in whose device enrollment fails, so an exclusive v2
        // verifier turned "migrated" into "permanently locked out" on the very next login.
        $v2 = str_repeat('5', 64);
        $token = $this->registerToken();
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a, 'authSecretV2' => $v2])[0]);
        $res = $this->api->addDevice(['token' => $token, 'authSecret' => $this->a, 'deviceKey' => str_repeat('8', 64)]);
        self::assertContains($res[0], [200, 201], 'a migrated account must still be able to enroll a device');
    }

    public function testProofOfWorkIsRequiredAndCannotBeReplayedOrForged(): void
    {
        $body = ['usernameHash' => str_repeat('1', 64), 'authSecret' => str_repeat('2', 64), 'identityKey' => str_repeat('3', 64)];
        // No proof at all.
        self::assertSame(400, $this->api->register($body)[0]);
        // A forged MAC over a challenge the server never issued.
        self::assertSame(400, $this->api->register([...$body, 'pow' => [
            'challenge' => str_repeat('a', 32), 'expiresAt' => 1_000_300, 'mac' => str_repeat('b', 64), 'nonce' => '1',
        ]])[0]);
        // A real challenge with a WRONG solution.
        $good = $this->pow();
        self::assertSame(400, $this->api->register([...$body, 'pow' => [...$good, 'nonce' => 'not-the-solution']])[0]);
        // The correct solution works exactly once; the SAME proof is refused the second time.
        self::assertSame(201, $this->api->register([...$body, 'pow' => $good])[0]);
        self::assertSame(400, $this->api->register([
            'usernameHash' => str_repeat('4', 64), 'authSecret' => str_repeat('2', 64), 'identityKey' => str_repeat('5', 64),
            'pow' => $good,
        ])[0], 'a spent challenge cannot be replayed into a second account');
    }

    public function testNobodyCanLockAnOwnerOutOfTheirAccountByGuessing(): void
    {
        // Two cuts of a per-account attempt limiter both turned into a weapon: anyone who knew a handle
        // could spend its budget with garbage and refuse the OWNER's correct passphrase, which also
        // locked them out of their own on-device vault. An earlier version of this very test asserted
        // that lockout while its name denied it, which is how the suite stayed green over the bug.
        //
        // Both an UNMIGRATED account (what every live account is today) and a migrated one must survive
        // a sustained wrong-guess flood.
        $v2 = str_repeat('5', 64);
        $this->registerToken(); // registered WITHOUT v2: unmigrated, the live-account state
        $wrong = str_repeat('0', 64);
        for ($i = 0; $i < 40; $i++) {
            self::assertSame(401, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $wrong])[0]);
        }
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a])[0],
            'an UNMIGRATED owner must still get in after a flood of wrong guesses');

        // Migrate, then flood again: still in, on either secret.
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a, 'authSecretV2' => $v2])[0]);
        for ($i = 0; $i < 40; $i++) {
            self::assertSame(401, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $wrong, 'authSecretV2' => $wrong])[0]);
        }
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a, 'authSecretV2' => $v2])[0]);
        self::assertSame(200, $this->api->login(['usernameHash' => $this->u, 'authSecret' => $this->a])[0]);
    }

    public function testAMissAndAWrongCredentialHitAreIndistinguishable(): void
    {
        // The existence oracle: an attacker never holds a matching v2 secret, so every real account fell
        // through to Argon2id (~150ms) while every absent one answered in ~1ms. A sweep separated them
        // with non-overlapping distributions. Both paths must run exactly ONE Argon2id.
        $this->registerToken();
        $wrong = str_repeat('0', 64);
        $t0 = microtime(true);
        $hit = $this->api->login(['usernameHash' => $this->u, 'authSecret' => $wrong]);
        $hitMs = (microtime(true) - $t0) * 1000;
        $t1 = microtime(true);
        $miss = $this->api->login(['usernameHash' => str_repeat('e', 64), 'authSecret' => $wrong]);
        $missMs = (microtime(true) - $t1) * 1000;

        self::assertSame($hit, $miss, 'the responses must be byte-identical');
        // Both pay a real Argon2id, so neither is in the "instant" range that gave the sweep its signal.
        self::assertGreaterThan(20, $hitMs, 'a wrong-credential hit must pay Argon2id');
        self::assertGreaterThan(20, $missMs, 'a miss must pay Argon2id too, or it is an existence oracle');
        // And they must be within the same order of magnitude of each other.
        $ratio = max($hitMs, $missMs) / max(0.001, min($hitMs, $missMs));
        self::assertLessThan(3.0, $ratio, "miss/hit timing ratio {$ratio} is a usable existence signal");
    }

    public function testRevokeDeletesTheDevicesKeyPackages(): void
    {
        $token1 = $this->registerToken();
        $this->api->publishKeys(['token' => $token1, 'keyPackages' => [
            ['keyPackage' => str_repeat('aa', 100), 'ref' => str_repeat('1', 64), 'lastResort' => false],
        ]]);
        $deviceId = self::currentOf($this->devicesOf($token1))['deviceId'];
        self::assertIsString($deviceId);
        $this->api->revokeDevice(['token' => $token1, 'deviceId' => $deviceId]);

        // The account now has no active device, so a directory claim returns nothing.
        $res = $this->api->takeKeys(['token' => $this->otherToken(), 'usernameHash' => $this->u]);
        self::assertSame([], $res[1]['devices']);
    }

    public function testServerAwayServedOnlyOnceEveryDeviceIsOffline(): void
    {
        $token = $this->registerToken();
        $other = $this->otherToken();
        // Setting away marks a fresh heartbeat, so while online the sender gets null (the client-side
        // away handles online replies), not the away text.
        self::assertSame(200, $this->api->setAway(['token' => $token, 'awayText' => 'back in an hour'])[0]);
        $look = $this->api->awayLookup(['token' => $other, 'usernameHash' => $this->u]);
        self::assertSame(200, $look[0]);
        self::assertNull($look[1]['away']);

        // At the store level, advance the clock past the offline TTL: now the away text is served.
        $pdo = (new Db(':memory:'))->pdo();
        $early = new UserStore($pdo, 1000);
        $early->register($this->u, $this->a, $this->k);
        $early->setAway($this->u, 'back in an hour'); // last_beat_at = 1000
        self::assertNull($early->lookupAway($this->u)); // online at t=1000
        $late = new UserStore($pdo, 1200); // 200s later, past the 90s TTL
        self::assertSame('back in an hour', $late->lookupAway($this->u));
        // A heartbeat refreshes liveness, suppressing the away text again.
        $late->beatAway($this->u);
        self::assertNull($late->lookupAway($this->u));
    }

    public function testPresenceSharedWhileFreshThenReadsOffline(): void
    {
        $token = $this->registerToken();
        $other = $this->otherToken();
        // A bad status is rejected; a valid one is shared.
        self::assertSame(400, $this->api->setPresence(['token' => $token, 'status' => 'bogus'])[0]);
        self::assertSame(200, $this->api->setPresence(['token' => $token, 'status' => 'away'])[0]);
        self::assertSame('away', $this->api->getPresence(['token' => $other, 'usernameHash' => $this->u])[1]['status']);
        // Off by default: a user who never opted in reads offline.
        self::assertSame('offline', $this->api->getPresence(['token' => $other, 'usernameHash' => str_repeat('9', 64)])[1]['status']);

        // A stale heartbeat reads offline (store-level clock); clearing turns it off.
        $pdo = (new Db(':memory:'))->pdo();
        $early = new UserStore($pdo, 1000);
        $early->register($this->u, $this->a, $this->k);
        $early->setPresence($this->u, 'online');
        self::assertSame('online', $early->getPresence($this->u));
        $late = new UserStore($pdo, 1200); // past the 90s TTL
        self::assertSame('offline', $late->getPresence($this->u));
        $early->clearPresence($this->u);
        self::assertSame('offline', $early->getPresence($this->u));
    }

    public function testPresenceRequiresAuth(): void
    {
        $this->registerToken();
        self::assertSame(401, $this->api->setPresence(['status' => 'online'])[0]);
        self::assertSame(401, $this->api->clearPresence([])[0]);
        self::assertSame(401, $this->api->getPresence(['usernameHash' => $this->u])[0]);
    }

    public function testPublishReplacesTheUnconsumedBacklogAndSparesConsumedAndLastResort(): void
    {
        $pdo = (new Db(':memory:'))->pdo();
        $store = new UserStore($pdo, 1000);
        $d1 = $store->register($this->u, $this->a, $this->k);
        self::assertIsString($d1);
        // First batch: two one-time packages plus a last-resort.
        $store->publishKeyPackages($this->u, $d1, [
            ['blob' => 'old1', 'ref' => str_repeat('1', 64), 'lastResort' => false],
            ['blob' => 'old2', 'ref' => str_repeat('2', 64), 'lastResort' => false],
            ['blob' => 'lr1', 'ref' => str_repeat('3', 64), 'lastResort' => true],
        ]);
        // Consume ONE of them (a peer claimed it): consumed rows are history and must survive.
        $claimed = $store->takeKeyPackages($this->u);
        self::assertSame('old1', $claimed[0]['keyPackage'] ?? null, 'oldest-first claim consumed old1');
        // Second publish REPLACES the unconsumed one-time backlog: a stale (possibly pre-authorization)
        // package must not linger to be served oldest-first later.
        $store->publishKeyPackages($this->u, $d1, [
            ['blob' => 'new1', 'ref' => str_repeat('4', 64), 'lastResort' => false],
            ['blob' => 'lr2', 'ref' => str_repeat('5', 64), 'lastResort' => true],
        ]);
        self::assertSame(1, $store->keyPackageCount($d1), 'only the fresh one-time package remains unconsumed');
        $next = $store->takeKeyPackages($this->u);
        self::assertSame('new1', $next[0]['keyPackage'] ?? null, 'the stale old2 was pruned; the fresh batch serves');
        // The last-resort was replaced by its own DELETE+INSERT and the consumed history row survives.
        $lrStmt = $pdo->query("SELECT kp_blob FROM key_packages WHERE is_last_resort = 1");
        self::assertNotFalse($lrStmt);
        self::assertSame(['lr2'], $lrStmt->fetchAll(PDO::FETCH_COLUMN));
        $consumedStmt = $pdo->query("SELECT kp_blob FROM key_packages WHERE consumed_at IS NOT NULL");
        self::assertNotFalse($consumedStmt);
        self::assertContains('old1', $consumedStmt->fetchAll(PDO::FETCH_COLUMN), 'the consumed row is history and stays');
    }

    public function testServerAwayRequiresAuthValidatesAndClears(): void
    {
        $token = $this->registerToken();
        $other = $this->otherToken();
        // Every away endpoint requires a live session.
        self::assertSame(401, $this->api->setAway(['awayText' => 'hi'])[0]);
        self::assertSame(401, $this->api->awayBeat([])[0]);
        self::assertSame(401, $this->api->awayLookup(['usernameHash' => $this->u])[0]);
        // Over-long away text is rejected (the cap is 560).
        self::assertSame(400, $this->api->setAway(['token' => $token, 'awayText' => str_repeat('x', 561)])[0]);
        // Empty text turns away off.
        self::assertSame(200, $this->api->setAway(['token' => $token, 'awayText' => 'away now'])[0]);
        $cleared = $this->api->setAway(['token' => $token, 'awayText' => '']);
        self::assertSame(200, $cleared[0]);
        self::assertFalse($cleared[1]['away']);
        // After clearing there is no row, so a lookup returns null even when offline.
        self::assertNull($this->api->awayLookup(['token' => $other, 'usernameHash' => $this->u])[1]['away']);
    }

    public function testRevocationRecordsAreStoredVerbatimAndServedBackToTheAccount(): void
    {
        // ADR-022 P7. The server is a dead drop for these blobs: it holds no account key, so it can
        // neither produce one nor judge one beyond its shape, and the client re-verifies every signature.
        $token = $this->registerToken();
        self::assertSame([], $this->api->listRevocations(['token' => $token])[1]['revocations']);

        $k2 = str_repeat('2', 64);
        $token2 = $this->loginToken();
        $deviceId2 = $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2])[1]['deviceId'];
        self::assertIsString($deviceId2);

        $record = str_repeat('ab', 140); // one 140-byte record as hex
        $res = $this->api->revokeDevice(['token' => $token, 'deviceId' => $deviceId2, 'record' => $record]);
        self::assertSame(200, $res[0]);
        self::assertTrue($res[1]['recordStored'], 'the client must be told the durable half landed');
        self::assertSame([$record], $this->api->listRevocations(['token' => $token])[1]['revocations']);
        // It also rides on list-devices, so a client cannot pair without having seen the denylist.
        self::assertSame([$record], $this->api->listDevices(['token' => $token])[1]['revocations']);

        // Re-posting the same record is idempotent: the revoke click retries, and a duplicate must not
        // appear twice (the client derives its epoch floor from the record COUNT).
        $this->api->revokeDevice(['token' => $token, 'deviceId' => $deviceId2, 'record' => $record]);
        self::assertSame([$record], $this->api->listRevocations(['token' => $token])[1]['revocations']);
    }

    public function testARevocationRecordIsRejectedUnlessItIsExactlyOneRecordShaped(): void
    {
        // The one place a client writes an opaque blob, so the shape check is the whole server-side
        // defense. Everything security-relevant about the contents is checked by the client instead.
        $token = $this->registerToken();
        $k2 = str_repeat('2', 64);
        $token2 = $this->loginToken();
        $deviceId2 = $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2])[1]['deviceId'];
        self::assertIsString($deviceId2);

        foreach ([str_repeat('ab', 139), str_repeat('ab', 141), 'AB' . str_repeat('ab', 139), 'zz' . str_repeat('ab', 139), '', 12345] as $bad) {
            $res = $this->api->revokeDevice(['token' => $token, 'deviceId' => $deviceId2, 'record' => $bad]);
            // The device is still revoked: burning the server row already succeeded and is not undone by
            // a record the server cannot judge. Only the record is refused, and the client is told so.
            self::assertSame(200, $res[0]);
            self::assertFalse($res[1]['recordStored'], 'a malformed record must be refused');
        }
        self::assertSame([], $this->api->listRevocations(['token' => $token])[1]['revocations']);

        // Revoking with NO record at all still works, so a pre-P7 client keeps functioning.
        $res = $this->api->revokeDevice(['token' => $token, 'deviceId' => $deviceId2]);
        self::assertSame(200, $res[0]);
        self::assertFalse($res[1]['recordStored']);
    }

    public function testOneAccountCannotSeeOrWriteAnotherAccountsRevocations(): void
    {
        $mine = $this->registerToken();
        $record = str_repeat('cd', 140);
        $k2 = str_repeat('2', 64);
        $token2 = $this->loginToken();
        $deviceId2 = $this->api->addDevice(['token' => $token2, 'authSecret' => $this->a, 'deviceKey' => $k2])[1]['deviceId'];
        self::assertIsString($deviceId2);
        $this->api->revokeDevice(['token' => $mine, 'deviceId' => $deviceId2, 'record' => $record]);

        // A second account sees NOTHING of the first account's denylist.
        $otherUser = str_repeat('9', 64);
        $this->api->register([
            'usernameHash' => $otherUser,
            'authSecret' => $this->a,
            'identityKey' => str_repeat('7', 64),
            'pow' => $this->pow(),
        ]);
        $otherToken = $this->api->login(['usernameHash' => $otherUser, 'authSecret' => $this->a])[1]['token'];
        self::assertIsString($otherToken);
        self::assertSame([], $this->api->listRevocations(['token' => $otherToken])[1]['revocations']);
        self::assertSame([$record], $this->api->listRevocations(['token' => $mine])[1]['revocations']);

        // And an unauthenticated caller sees nothing at all.
        self::assertSame(401, $this->api->listRevocations([])[0]);
        self::assertSame(401, $this->api->listRevocations(['token' => 'nope'])[0]);
    }
}
