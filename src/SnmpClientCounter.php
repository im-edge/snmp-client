<?php

namespace IMEdge\SnmpClient;

class SnmpClientCounter
{
    public int $sentMessages = 0;
    public int $sentRequests = 0;
    public int $sentBytes = 0;
    public int $receivedInvalidPackets = 0;
    public int $receivedMessages = 0;
    public int $receivedResponses = 0;
    public int $receivedReports = 0;
}
