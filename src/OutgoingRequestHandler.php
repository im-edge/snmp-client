<?php

namespace IMEdge\SnmpClient;

use Amp\DeferredFuture;
use IMEdge\SnmpClient\Error\SnmpTimeoutError;
use IMEdge\SnmpPacket\Pdu\Pdu;
use IMEdge\SnmpPacket\RequestIdConsumer;
use IMEdge\SnmpPacket\SimpleRequestIdGenerator;
use Revolt\EventLoop;
use Throwable;

class OutgoingRequestHandler implements TimeoutSlotHandler, RequestIdConsumer
{
    protected int $requestTimeout = 3;

    /** @var array<int, DeferredFuture<Pdu>> */
    protected array $pendingRequests = [];
    protected TimeoutTimer $timeoutTimer;
    /** @var array<int, int[]> */
    protected array $timeoutSlots = [];
    /** @var array<int, int> */
    protected array $requestTimeoutSlot = [];
    protected SimpleRequestIdGenerator $idGenerator;

    public function __construct()
    {
        $this->idGenerator = new SimpleRequestIdGenerator();
        $this->idGenerator->registerConsumer($this);
        $this->timeoutTimer = new TimeoutTimer($this);
    }

    /**
     * @return DeferredFuture<Pdu>
     */
    public function schedulePdu(Pdu $pdu): DeferredFuture
    {
        $id = $pdu->requestId;
        if ($id === null) {
            $id = $pdu->requestId = $this->idGenerator->getNextId();
        } else {
            if (isset($this->pendingRequests[$id])) {
                throw new \RuntimeException(sprintf('Request ID %s is already pending', $id));
            }
        }
        $this->pendingRequests[$id] = $deferred = new DeferredFuture();
// print_r(array_keys($this->pendingRequests));
        $this->scheduleTimeout($id, $this->requestTimeout);

        return $deferred;
    }

    protected function scheduleTimeout(int $id, int $timeout): void
    {
        $slot = $this->timeoutTimer->schedule($timeout);
        $this->timeoutSlots[$slot] ??= [];
        $this->timeoutSlots[$slot][$id] = $id;
        $this->requestTimeoutSlot[$id] = $slot;
    }

    /**
     * @return DeferredFuture<Pdu>|null
     */
    public function complete(?int $id): ?DeferredFuture
    {
        if ($id === null) {
            return null;
        }
        unset($this->timeoutSlots[$this->requestTimeoutSlot[$id] ?? null][$id]);
        $deferred = $this->pendingRequests[$id] ?? null;
        unset($this->pendingRequests[$id]);
        return $deferred;
    }

    public function rejectAll(Throwable $error): void
    {
        foreach ($this->listPendingIds() as $id) {
            $this->reject($id, $error);
        }
    }

    public function reject(int $id, Throwable $error): void
    {
        $deferred = $this->pendingRequests[$id] ?? null;
        if ($deferred === null) {
            printf("Failed to reject %d with '%s', it's gone\n", $id, $error->getMessage());
            return;
        }
        unset($this->pendingRequests[$id]);
        unset($this->timeoutSlots[$this->requestTimeoutSlot[$id] ?? null][$id]);
        EventLoop::defer(fn () => $deferred->error($error));
    }

    /**
     * @return int[]
     */
    protected function listPendingIds(): array
    {
        return array_keys($this->pendingRequests);
    }

    public function hasId(int $id): bool
    {
        return isset($this->pendingRequests[$id]);
    }

    public function triggerTimeoutSlot(int $slot): void
    {
        foreach ($this->timeoutSlots[$slot] ?? [] as $requestId) {
            $this->reject($requestId, new SnmpTimeoutError("Timeout for request $requestId in slot $slot"));
        }
        unset($this->timeoutSlots[$slot]);
    }

    public function __destruct()
    {
        unset($this->timeoutTimer);
    }
}
