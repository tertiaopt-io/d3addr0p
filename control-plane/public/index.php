<?php

declare(strict_types=1);

namespace DeadDrop\ControlPlane;

// Before anything that can fail, including the autoloader: an uncaught error must never render its
// message into the response body. PHP's default display_errors prints the file path, the line, and for
// a PDOException the SQL text - server internals, handed to an unauthenticated caller.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once __DIR__ . '/../vendor/autoload.php';

/*
 * Front controller for the control plane. It serves the account/identity tier only and never sees
 * message bytes (§4). Routes:
 *   GET  /healthz                health check
 *   POST /api/challenge         {}                                       -> 200 {challenge,expiresAt,mac,bits}
 *   POST /api/register          { usernameHash, authSecret, identityKey, authSecretV2?, pow } -> 201 | 409
 *   POST /api/login             { usernameHash, authSecret, authSecretV2? }   -> 200 {token} | 401
 *   POST /api/lookup            { token, usernameHash }                   -> 200 {activeDeviceKey,deviceKeys} | 401
 *   POST /api/add-device        { token, authSecret, deviceKey }          -> 201|200 {deviceId} | 409 | 401
 *   POST /api/list-devices      { token }                     -> 200 {devices,accountEpoch,revocations} | 401
 *   POST /api/revoke-device     { token, deviceId, record? }  -> 200 {ok,recordStored} | 404 | 401
 *   POST /api/revocations       { token }                                 -> 200 {revocations} | 401
 *   POST /api/publish-keys      { token, keyPackages[] }                  -> 201 {stored} | 409 | 401
 *   POST /api/take-keys         { token, usernameHash }                   -> 200 {devices} | 429 | 401
 *   POST /api/away              { token, usernameHash }                   -> 200 {away}    | 401
 *   POST /api/presence          { token, usernameHash }                   -> 200 {status}  | 401
 * Every wire field is a client-computed 64-hex value, so the server never sees a plaintext username
 * or a passphrase. Request bodies are the one place `mixed` enters; they are narrowed at once (§6).
 *
 * The four cross-user reads (lookup, take-keys, away, presence) answer a miss and an exhausted probe
 * budget with the SAME body, so neither the directory nor the throttle is an enumeration oracle; see
 * UserStore::allowProbe. lookup no longer has a 404 at all.
 */

/*
 * One generic 500 for anything that escapes a handler (a PDOException from a locked or corrupt
 * database is the realistic case). The body is a literal, not json_encode of anything derived from the
 * throwable, so there is no path by which a message, a file path, a SQL fragment or a bound username
 * hash reaches the caller - and nothing here can throw on its own. The exception's location goes to the
 * server error log; its MESSAGE deliberately does not, since it can carry request data and the log
 * outlives the request on disk.
 */
set_exception_handler(static function (\Throwable $e): void {
    error_log('control-plane: unhandled ' . $e::class . ' at ' . $e->getFile() . ':' . $e->getLine());
    if (!headers_sent()) {
        header('Content-Type: application/json');
        http_response_code(500);
    }
    echo '{"error":"server_error"}';
});

header('Content-Type: application/json');

$method = is_string($_SERVER['REQUEST_METHOD'] ?? null) ? $_SERVER['REQUEST_METHOD'] : 'GET';
$path = is_string($_SERVER['REQUEST_URI'] ?? null)
    ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)
    : '/';

/** @return array<array-key, mixed> */
function dd_read_json_body(): array
{
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

/** @param array<string, mixed> $body */
function dd_respond(int $status, array $body): void
{
    http_response_code($status);
    echo json_encode($body, JSON_THROW_ON_ERROR);
}

if ($path === '/healthz' || $path === '/api/healthz') {
    dd_respond(200, (new Health(true))->toResponse());
    exit;
}

$dbPath = getenv('DD_DB_PATH');
if (!is_string($dbPath) || $dbPath === '') {
    $dbPath = dirname(__DIR__) . '/data/accounts.db';
}
$dbDir = dirname($dbPath);
if (!is_dir($dbDir)) {
    @mkdir($dbDir, 0700, true);
}

$api = new Api(new UserStore((new Db($dbPath))->pdo(), time()));

if ($method === 'POST' && $path === '/api/challenge') {
    [$status, $body] = $api->challenge();
    dd_respond($status, $body);
    exit;
}

if ($method === 'POST' && $path === '/api/register') {
    [$status, $body] = $api->register(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/login') {
    [$status, $body] = $api->login(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/lookup') {
    [$status, $body] = $api->lookup(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/add-device') {
    [$status, $body] = $api->addDevice(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/list-devices') {
    [$status, $body] = $api->listDevices(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/revoke-device') {
    [$status, $body] = $api->revokeDevice(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/revocations') {
    [$status, $body] = $api->listRevocations(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/publish-keys') {
    [$status, $body] = $api->publishKeys(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/take-keys') {
    [$status, $body] = $api->takeKeys(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/set-away') {
    [$status, $body] = $api->setAway(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/away-beat') {
    [$status, $body] = $api->awayBeat(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/away') {
    [$status, $body] = $api->awayLookup(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/set-presence') {
    [$status, $body] = $api->setPresence(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/clear-presence') {
    [$status, $body] = $api->clearPresence(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/presence') {
    [$status, $body] = $api->getPresence(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}
if ($method === 'POST' && $path === '/api/delete-account') {
    [$status, $body] = $api->deleteAccount(dd_read_json_body());
    dd_respond($status, $body);
    exit;
}

dd_respond(404, ['error' => 'not_found']);
