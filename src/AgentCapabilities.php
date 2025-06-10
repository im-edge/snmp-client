<?php

namespace IMEdge\SnmpClient;

class AgentCapabilities
{
    /** @var array<int, AgentCapability> indexed by AgentCapability->value */
    protected array $capabilities = [];

    /**
     * @param AgentCapability[] $capabilities
     */
    public function __construct(array $capabilities = [])
    {
        foreach ($capabilities as $capability) {
            $this->add($capability);
        }
    }

    public function add(AgentCapability $capability): void
    {
        $this->capabilities[$capability->value] = $capability;
    }

    public function has(AgentCapability $capability): bool
    {
        return isset($this->capabilities[$capability->value]);
    }

    /**
     * @return array<int, AgentCapability>
     */
    public function getCapabilities(): array
    {
        return $this->capabilities;
    }
}
