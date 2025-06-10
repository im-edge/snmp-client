<?php

namespace IMEdge\SnmpClient;

use Revolt\EventLoop;

class TimeoutTimer
{
    // 1.000.000.000 / 4 -> 4 slots per second
    protected const GRANULARITY = 250_000_000;
    /** @var array<int, string> */
    protected array $timeoutTimers = [];
    public function __construct(
        protected TimeoutSlotHandler $handler
    ) {
    }

    public function schedule(int $delay): int
    {
        $slot = (int) (hrtime(true) / self::GRANULARITY) + 1;
        $this->timeoutTimers[$slot] ??= EventLoop::delay($delay, fn () => $this->trigger($slot));

        return $slot;
    }

    protected function trigger(int $slot): void
    {
        $this->handler->triggerTimeoutSlot($slot);
        unset($this->timeoutTimers[$slot]);
    }

    public function __destruct()
    {
        unset($this->handler);
        foreach ($this->timeoutTimers as $timer) {
            EventLoop::cancel($timer);
        }
    }
}
