<?php

namespace IMEdge\SnmpClient;

interface TimeoutSlotHandler
{
    public function triggerTimeoutSlot(int $slot): void;
}
