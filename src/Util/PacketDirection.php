<?php

namespace IMEdge\SnmpClient\Util;

enum PacketDirection: string
{
    case INCOMING = 'incoming';
    case OUTGOING = 'outgoing';
}
