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
    private string $u;
    private string $a;
    private string $k; // the first device key

    protected function setUp(): void
    {
        $this->api = new Api(new UserStore((new Db(':memory:'))->pdo(), 1_000_000));
        $this->u = str_repeat('a', 64);
        $this->a = str_repeat('b', 64);
        $this->k = str_repeat('c', 64);
    }

    /** @param array<array-key, mixed> $body */
    private function register(array $body): int
    {
        return $this->api->register($body)[0];
    }

    private function registerToken(): string
    {
        $res = $this->api->register(['usernameHash' => $this->u, 'authSecret' => $this->a, 'identityKey' => $this->k]);
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
        $this->api->register(['usernameHash' => $u2, 'authSecret' => $a2, 'identityKey' => str_repeat('7', 64)]);
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

    public function testLookupReturnsTheActiveDeviceKeyForAuthenticatedSessions(): void
    {
        $token = $this->registerToken();
        $ok = $this->api->lookup(['token' => $token, 'usernameHash' => $this->u]);
        self::assertSame(200, $ok[0]);
        self::assertSame($this->k, $ok[1]['activeDeviceKey']);
        self::assertSame([$this->k], $ok[1]['deviceKeys']);

        self::assertSame(401, $this->api->lookup(['usernameHash' => $this->u])[0]); // no token
        self::assertSame(404, $this->api->lookup(['token' => $token, 'usernameHash' => str_repeat('f', 64)])[0]); // unknown user
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
        $this->api->register(['usernameHash' => $u2, 'authSecret' => $a2, 'identityKey' => str_repeat('7', 64)]);
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
        $early = new Api(new UserStore($pdo, 1000));
        $reg = $early->register(['usernameHash' => $this->u, 'authSecret' => $this->a, 'identityKey' => $this->k]);
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
        // A single caller may claim against one target up to the per-window ceiling (30); the very next
        // claim in the same window is rate-limited, bounding a prekey-exhaustion drain loop.
        for ($i = 0; $i < 30; $i++) {
            self::assertSame(200, $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u])[0]);
        }
        self::assertSame(429, $this->api->takeKeys(['token' => $other, 'usernameHash' => $this->u])[0]);
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
}
