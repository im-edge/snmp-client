<?php

namespace IMEdge\SnmpClient;

enum AgentReachability: string
{
    case PENDING = 'pending';
    case REACHABLE = 'reachable';
    case UNREACHABLE = 'unreachable';
}
