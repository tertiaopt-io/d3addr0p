<?php

declare(strict_types=1);

namespace DeadDrop\ControlPlane;

/**
 * Liveness state for the control plane.
 *
 * The control plane handles account/identity/config APIs only. It never receives, stores,
 * or forwards message bytes (brief §4 tiering), so nothing here references payloads, senders,
 * recipients, or routing keys.
 */
final class Health
{
    public function __construct(
        private readonly bool $ready,
    ) {
    }

    public function isReady(): bool
    {
        return $this->ready;
    }

    /**
     * @return array{status: string}
     */
    public function toResponse(): array
    {
        return ['status' => $this->ready ? 'ok' : 'starting'];
    }
}
