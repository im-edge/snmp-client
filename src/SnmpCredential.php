<?php

namespace IMEdge\SnmpClient;

use IMEdge\SnmpPacket\SnmpSecurityLevel;
use IMEdge\SnmpPacket\SnmpVersion;
use IMEdge\SnmpPacket\Usm\SnmpAuthProtocol;
use IMEdge\SnmpPacket\Usm\SnmpPrivProtocol;

class SnmpCredential
{
    public function __construct(
        public readonly ?SnmpVersion $version = null,
        public readonly ?string $securityName = null, // SNMPv1/2c community string, v3 user
        public readonly ?SnmpSecurityLevel $securityLevel = null,
        public readonly ?SnmpAuthProtocol $authProtocol = null,
        public readonly ?string $authKey = null,
        public readonly ?SnmpPrivProtocol $privProtocol = null,
        public readonly ?string $privKey = null,
    ) {
    }
}
