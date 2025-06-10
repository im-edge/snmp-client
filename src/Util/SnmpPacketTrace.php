<?php

namespace IMEdge\SnmpClient\Util;

use Amp\Socket\InternetAddress;
use IMEdge\SnmpPacket\Message\SnmpMessage;
use IMEdge\SnmpPacket\SnmpMessageInspector;

class SnmpPacketTrace
{
    public function append(SnmpMessage $message, PacketDirection $direction, InternetAddress $peer): void
    {
        $msg = sprintf('%s (%s)', ucfirst($direction->value), $peer);
        printf("\n%s\n%s\n", $msg, str_repeat('-', strlen($msg)));
        SnmpMessageInspector::dump($message);
    }
}
