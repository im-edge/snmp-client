<?php

namespace IMEdge\SnmpClient;

class AgentState
{
    public function __construct(
        public AgentReachability $reachability = AgentReachability::PENDING,
    ) {
    }
}
