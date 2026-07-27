<?php

declare(strict_types=1);

namespace DeadDrop\ControlPlane;

require_once __DIR__ . '/../vendor/autoload.php';

/*
 * Front controller for the control plane. It serves the account/identity tier only and never sees
 * message bytes (§4). Routes:
 *   GET  /healthz                health check
 *   POST /api/register          { usernameHash, authSecret, identityKey } -> 201 {token,deviceId} | 409
 *   POST /api/login             { usernameHash, authSecret }              -> 200 {token} | 401
 *   POST /api/lookup            { token, usernameHash }                   -> 200 {activeDeviceKey,deviceKeys} | 404 | 401
 *   POST /api/add-device        { token, authSecret, deviceKey }          -> 201|200 {deviceId} | 409 | 401
 *   POST /api/list-devices      { token }                                 -> 200 {devices} | 401
 *   POST /api/revoke-device     { token, deviceId }                       -> 200 {ok} | 404 | 401
 *   POST /api/publish-keys      { token, keyPackages[] }                  -> 201 {stored} | 409 | 401
 *   POST /api/take-keys         { token, usernameHash }                   -> 200 {devices} | 401
 * Every wire field is a client-computed 64-hex value, so the server never sees a plaintext username
 * or a passphrase. Request bodies are the one place `mixed` enters; they are narrowed at once (§6).
 */

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
