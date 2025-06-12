<?php

namespace IMEdge\SnmpClient;

use Amp\Future;
use Amp\Socket\InternetAddress;
use Amp\Socket\InternetAddressVersion;
use Amp\Socket\ResourceUdpSocket;
use Exception;
use IMEdge\SnmpClient\Error\SnmpTimeoutError;
use IMEdge\SnmpClient\Usm\ClientContext;
use IMEdge\SnmpClient\Util\PacketDirection;
use IMEdge\SnmpClient\Util\SnmpPacketTrace;
use IMEdge\SnmpPacket\Message\VarBind;
use IMEdge\SnmpPacket\Message\VarBindList;
use IMEdge\SnmpPacket\Pdu\GetBulkRequest;
use IMEdge\SnmpPacket\Pdu\GetNextRequest;
use IMEdge\SnmpPacket\Pdu\GetRequest;
use IMEdge\SnmpPacket\IncrementingRequestIdGenerator;
use IMEdge\SnmpPacket\Pdu\Pdu;
use IMEdge\SnmpPacket\Pdu\Report;
use IMEdge\SnmpPacket\Pdu\Response;
use IMEdge\SnmpPacket\Message\SnmpMessage;
use IMEdge\SnmpPacket\SnmpSecurityLevel;
use IMEdge\SnmpPacket\Message\SnmpV1Message;
use IMEdge\SnmpPacket\Message\SnmpV2Message;
use IMEdge\SnmpPacket\Message\SnmpV3Header;
use IMEdge\SnmpPacket\Message\SnmpV3Message;
use IMEdge\SnmpPacket\Message\SnmpV3ScopedPdu;
use IMEdge\SnmpPacket\SnmpVersion;
use IMEdge\SnmpPacket\Pdu\TrapV2;
use IMEdge\SnmpPacket\Error\SnmpAuthenticationException;
use IMEdge\SnmpPacket\Usm\UserBasedSecurityModel;
use IMEdge\SnmpPacket\Usm\UsmStats;
use IMEdge\SnmpPacket\VarBindValue\ContextSpecific;
use Psr\Log\LoggerInterface;
use Revolt\EventLoop;
use RuntimeException;
use Throwable;

use function Amp\delay;
use function Amp\Socket\bindUdpSocket;

/**
 * Simple SNMP Client
 *
 * Provides interactive PDU and Message Dispatching, should not be used as the regular IMEdge poller
 */
class SnmpClient
{
    /** @var array<int, ClientContext> */
    protected array $pendingMessagesV3 = [];
    /** @var ClientContext[] */
    protected array $clients = [];
    protected IncrementingRequestIdGenerator $messageIdGenerator;
    protected OutgoingRequestHandler $outgoingRequests;
    protected SnmpClientCounter $counter;
    public ?SnmpPacketTrace $trace = null;
    protected ?ResourceUdpSocket $socket = null;
    protected ?ResourceUdpSocket $socket6 = null;

    public function __construct(
        protected ?LoggerInterface $logger = null,
        protected InternetAddress $socketAddress = new InternetAddress('0.0.0.0', 0),
        protected InternetAddress $socketAddress6 = new InternetAddress('::', 0),
    ) {
        $this->counter = new SnmpClientCounter();
        $this->outgoingRequests = new OutgoingRequestHandler();
        $this->messageIdGenerator = new IncrementingRequestIdGenerator();
    }

    /**
     * @param array<string, ?string> $oids
     * @throws SnmpAuthenticationException
     */
    public function get(string $target, array $oids): Pdu
    {
        return $this->sendRequestPdu($target, new GetRequest(self::oidsToVarBindList($oids)));
    }

    /**
     * @param array<string, ?string> $oids
     * @throws SnmpAuthenticationException
     */
    public function getNext(string $target, array $oids): Pdu
    {
        return $this->sendRequestPdu($target, new GetNextRequest(self::oidsToVarBindList($oids)));
    }

    /**
     * @param array<string, ?string> $oids
     * @throws SnmpAuthenticationException
     */
    public function getBulk(
        string $target,
        array $oids,
        int $maxRepetitions = 10,
        int $nonRepeaters = 0
    ): Pdu {
        return $this->sendRequestPdu(
            $target,
            new GetBulkRequest(self::oidsToVarBindList($oids), null, $maxRepetitions, $nonRepeaters)
        );
    }

    /**
     * @param array<string, ?string> $oids
     * @param array<string, ?string>|null $baseOids
     * @return array<string, VarBind|VarBind[]>
     * @throws SnmpAuthenticationException
     */
    public function getBulkNormalized(
        string $target,
        array $oids,
        ?array $baseOids = null,
        int $maxRepetitions = 10,
        int $nonRepeaters = 0
    ): array {
        $baseOids ??= $oids;
        $request = new GetBulkRequest(self::oidsToVarBindList($oids), null, $maxRepetitions, $nonRepeaters);
        $result = $this->sendRequestPdu($target, $request);
        $nonRepeaters = $request->nonRepeaters;
        $results = [];
        $varBinds = $result->varBinds->varBinds;
        $repeaters = $baseOids;
        for ($i = 1; $i <= $nonRepeaters; $i++) {
            if ($varBind = array_shift($varBinds)) {
                $name = array_shift($repeaters);
                $results[$name ?? $varBind->oid] = $varBind;
            } else {
                throw new \ValueError('Response does not contain all requested non-repeaters');
            }
        }
        $repeaters = array_keys($repeaters);
        $i = 0;
        /** @var VarBind $varBind */
        while ($varBind = array_shift($varBinds)) {
            $prefix = $repeaters[$i];
            $name = $baseOids[$prefix] ?? $prefix;
            if ($varBind->value instanceof ContextSpecific) {
                $results[$name] ??= [];
            } elseif (str_starts_with($varBind->oid, $prefix)) {
                assert(is_array($results[$name])); // TODO: check this
                $results[$name][substr($varBind->oid, strlen($prefix) + 1)] = $varBind;
            } else { // Hint: skipping all others
                $results[$name] ??= [];
            }
            $i++;
            if ($i === count($repeaters)) {
                $i = 0;
            }
        }

        return $results;
    }

    /**
     * @param array<string, ?string> $oids
     * @throws SnmpAuthenticationException
     * @return array<string, VarBind|VarBind[]|null>
     */
    public function table(
        string $target,
        array $oids,
        int $maxRepetitions = 10,
        int $nonRepeaters = 0
    ): array {
        $tables = [];
        $fetch = $oids;
        $base = $oids;
        while (! empty($fetch)) {
            $results = $this->getBulkNormalized($target, $fetch, $base, $maxRepetitions, $nonRepeaters);
            $fetch = [];
            if ($nonRepeaters > 0) {
                for ($i = 1; $i <= $nonRepeaters; $i++) {
                    $tables[array_key_first($results)] = array_shift($results);
                    array_shift($base);
                }
                $nonRepeaters = 0;
            }
            $done = [];
            foreach ($base as $oid => $alias) {
                $key = $alias ?? $oid;
                assert(is_array($results[$key])); // sure?
                if (isset($tables[$key])) {
                    assert(is_array($tables[$key])); // sure?
                    foreach ($results[$key] as $k => $v) {
                        $tables[$key][$k] = $v;
                    }
                } else {
                    $tables[$key] = $results[$key];
                }
                if (count($results[$key]) < $maxRepetitions) {
                    $done[] = $oid;
                } else {
                    $fetch[$results[$key][array_key_last($results[$key])]->oid] = $alias;
                }
            }
            foreach ($done as $oid) {
                unset($fetch[$oid]);
                unset($base[$oid]);
            }

//            delay(160);
        }

        return $tables;
    }

    /**
     * @param array<string, ?string> $oids
     */
    protected static function oidsToVarBindList(array $oids): VarBindList
    {
        return new VarBindList(self::oidsToVarBindsForRequest($oids));
    }

    /**
     * @param array<string, ?string> $oids
     * @return VarBind[]
     */
    protected static function oidsToVarBindsForRequest(array $oids): array
    {
        $varBinds = [];
        $i = 0;
        foreach (array_keys($oids) as $oid) {
            $i++;
            $varBinds[$i] = new VarBind($oid);
        }

        return $varBinds;
    }

    /**
     * @throws SnmpAuthenticationException
     */
    public function registerTarget(string $id, InternetAddress $address, SnmpCredential $credential): void
    {
        $this->clients[$id] = new ClientContext($address, $credential);
    }

    /**
     * @throws SnmpAuthenticationException
     */
    public function sendRequestPdu(string $targetId, Pdu $pdu): Pdu
    {
        return $this->sendAsyncRequestPdu($targetId, $pdu)->await();
    }

    /**
     * @return Future<Pdu>
     */
    protected function sendAsyncRequestPdu(string $targetId, Pdu $pdu): Future
    {
        $client = $this->requireClient($targetId);
        $deferred = $this->outgoingRequests->schedulePdu($pdu);
        try {
            $this->sendPduToClient($client, $pdu);
        } catch (Throwable $e) {
            if (! $e instanceof SnmpTimeoutError) {
                if ($id = $pdu->requestId) {
                    $this->outgoingRequests->reject($id, $e);
                } else {
                    $deferred->error($e);
                }
            }
        }

        return $deferred->getFuture();
    }

    /**
     * @throws SnmpAuthenticationException
     */
    public function sendPduToClient(ClientContext $client, Pdu $pdu): void
    {
        switch ($client->credential->version) {
            case SnmpVersion::v1:
            case SnmpVersion::v2c:
                $this->sendPduV1($client, $pdu);
                break;
            case SnmpVersion::v3:
                $this->sendPduV3($client, $pdu);
                break;
        }
    }

    protected function socket(InternetAddressVersion $ipVersion): ResourceUdpSocket
    {
        switch ($ipVersion) {
            case InternetAddressVersion::IPv4:
                if ($this->socket === null) {
                    $this->socket = bindUdpSocket($this->socketAddress);
                    EventLoop::queue($this->keepReadingFromSocket(...));
                }

                return $this->socket;
            case InternetAddressVersion::IPv6:
                if ($this->socket6 === null) {
                    $this->socket6 = bindUdpSocket($this->socketAddress6);
                    EventLoop::queue($this->keepReadingFromSocket6(...));
                }

                return $this->socket6;
        }
    }

    protected function handleIncomingMessage(SnmpV1Message|SnmpV2Message $message, InternetAddress $peer): void
    {
        $pdu = $message->getPdu();

        // TODO: track v1/2 peers based on request ID
        if ($pdu instanceof TrapV2) {
            // $this->emit(self::ON_TRAP, [$message, $peer]);
            return;
        }

        if (! $deferred = $this->outgoingRequests->complete($pdu->requestId)) {
            return;
        }

        if ($pdu->errorStatus->isError()) {
            $deferred->error(
                new SnmpAuthenticationException('PDU has error -> TODO')
            );
            return;
        }
        if ($pdu instanceof Response) {
            $deferred->complete($pdu);
        }
    }

    protected function handleIncomingResponse(Pdu $pdu): void
    {
        if ($deferred = $this->outgoingRequests->complete($pdu->requestId)) {
            $deferred->complete($pdu);
        }
    }

    protected function handleIncomingV3Message(SnmpV3Message $message, InternetAddress $peer): void
    {
        $id = $message->header->messageId;
        $clientContext = $this->pendingMessagesV3[$id] ?? null;
        if ($clientContext?->address->toString() !== $peer->toString()) {
            $this->logger?->warning(sprintf(
                "Peer address %s doesn't match the expected one (%s)\n",
                $peer,
                $clientContext?->address ?? 'none'
            ));
            return;
        }
        unset($this->pendingMessagesV3[$id]);
        /** @phpstan-ignore identical.alwaysFalse */ // Can be null, PHPStan doesn't get id. Or is it me?
        if ($clientContext === null) {
            $this->logger?->warning("No client context for $id");
            return;
        }
        try {
            if ($check = $clientContext->handleIncomingV3Message($message)) {
                if ($check === true) {
                    $this->trace?->append($message, PacketDirection::INCOMING, $peer);
                    $this->handleIncomingResponse($message->getPdu());
                } elseif ($check instanceof Pdu) {
                    if ($this->trace) {
                        // TODO: Clone?
                        $message->scopedPdu->pdu = $check;
                        $this->trace->append($message, PacketDirection::INCOMING, $peer);
                    }
                    $this->handleIncomingResponse($check);
                }
            } else {
                // Check says NO
                $this->trace?->append($message, PacketDirection::INCOMING, $peer);
            }
        } catch (Exception $e) {
            $this->trace?->append($message, PacketDirection::INCOMING, $peer);
            if ($requestId = $message->scopedPdu->pdu?->requestId ?? null) {
                if ($deferred = $this->outgoingRequests->complete($requestId)) {
                    $deferred->error($e);
                }
            }
        }
    }

    protected function handleData(string $data, InternetAddress $peer): void
    {
        // TODO: Logger::debug("Got message from $peer");
        try {
            $message = SnmpMessage::fromBinary($data);
            $this->counter->receivedMessages++;
            if ($message instanceof SnmpV3Message) {
                $this->handleIncomingV3Message($message, $peer);
            } elseif ($message instanceof SnmpV1Message) { // || instanceof SnmpV2Message (extends SnmpV1Message)
                $this->handleIncomingMessage($message, $peer);
            }
        } catch (Exception $e) {
            $this->logger?->error($e->getMessage());
            $this->counter->receivedInvalidPackets++;
        }
    }

    protected function keepReadingFromSocket(): void
    {
        if ($this->socket === null) {
            throw new RuntimeException('Cannot register socket handlers w/o socket');
        }
        try {
            while ($received = $this->socket?->receive()) {
                [$address, $data] = $received;
                $this->handleData($data, $address);
            }
            $this->socket = null;
            $this->outgoingRequests->rejectAll(new Exception('Socket has been closed'));
        } catch (Throwable $error) {
            $this->outgoingRequests->rejectAll($error);
            if ($this->socket !== null) {
                $this->socket->close();
                $this->socket = null;
            }
        }
    }

    protected function keepReadingFromSocket6(): void
    {
        if ($this->socket6 === null) {
            throw new RuntimeException('Cannot register socket6 handlers w/o socket');
        }
        try {
            while ($received = $this->socket6?->receive()) {
                [$address, $data] = $received;
                $this->handleData($data, $address);
            }
            $this->socket = null;
            $this->outgoingRequests->rejectAll(new Exception('Socket6 has been closed'));
        } catch (Throwable $error) {
            $this->outgoingRequests->rejectAll($error);
            if ($this->socket6 !== null) {
                $this->socket6->close();
                $this->socket6 = null;
            }
        }
    }

    protected function requireClient(string $targetId): ClientContext
    {
        return $this->clients[$targetId] ?? throw new RuntimeException('Unknown target: ' . $targetId);
    }

    protected function reserveMessageId(ClientContext $context): int
    {
        $id = $this->messageIdGenerator->getNextId();
// echo "Reserved message id $id\n";
        $this->pendingMessagesV3[$id] = $context;

        return $id;
    }

    protected static function discoveryMessage(int $messageId, Pdu $pdu): SnmpV3Message
    {
        return new SnmpV3Message(
            new SnmpV3Header(
                messageId: $messageId,
                securityFlags: SnmpSecurityLevel::NO_AUTH_NO_PRIV,
                reportableFlag: true,
            ),
            new UserBasedSecurityModel(),
            SnmpV3ScopedPdu::forPdu($pdu)
        );
    }

    protected function sendAndWaitForDiscovery(ClientContext $context): Pdu
    {
        $pdu = new GetRequest();
        $deferred = $this->outgoingRequests->schedulePdu($pdu);
        $message = self::discoveryMessage($this->reserveMessageId($context), $pdu);
        $this->sendMessage($message, $context->address);
        delay(0); // TODO: test, whether and how this influences async operation
        return $deferred->getFuture()->await();
    }

    protected function sendMessage(SnmpMessage $message, InternetAddress $address): void
    {
        $this->trace?->append($message, PacketDirection::OUTGOING, $address);
        $this->socket($address->getVersion())->send($address, $message->toBinary());
    }

    protected function sendPduV1(ClientContext $context, Pdu $pdu): void
    {
        $this->sendMessage($context->prepareMessage($pdu), $context->address);
    }

    /**
     * @throws SnmpAuthenticationException
     */
    protected function sendPduV3(ClientContext $context, Pdu $pdu): void
    {
        if (! $context->wantsAuthentication()) {
            $this->sendMessage(
                $context->prepareUnauthenticatedMessage($pdu, $this->reserveMessageId($context)),
                $context->address
            );
            return;
        }

        $originalId = $pdu->requestId;
        if (!$context->engine->hasId()) {
            try {
                $this->sendAndWaitForDiscovery($context);
            } catch (Exception $e) {
                $this->outgoingRequests->complete($originalId)?->error($e);
                return;
            }
            /** @phpstan-ignore booleanNot.alwaysTrue */ // async operation changes the engine. Does it??
            if (!$context->engine->hasId()) {
                $this->outgoingRequests->complete($originalId)?->error(
                    new SnmpAuthenticationException('Failed to retrieve Engine ID')
                );
                return;
            }
        }

        $pdu->requestId = null;
        $messageId = $this->reserveMessageId($context);
        $deferred = $this->outgoingRequests->schedulePdu($pdu);
        $this->sendMessage($context->prepareMessage($pdu, $messageId), $context->address);
        delay(0); // TODO: test, whether and how this influences async operation
        try {
            $responsePdu = $deferred->getFuture()->await();
        } catch (Exception $e) {
            $this->logger?->error($e->getMessage());
            $this->outgoingRequests->complete($originalId)?->error($e);
            return;
        }
        if ($responsePdu->errorStatus->isError()) {
            $this->outgoingRequests->complete($originalId)?->error(
                new SnmpAuthenticationException('PDU has error -> TODO, not auth issue')
            );
            return;
        }
        if ($responsePdu instanceof Report) {
            $varBinds = $responsePdu->varBinds;
            if ($varBinds->hasOid(UsmStats::WRONG_DIGESTS)) {
                $this->outgoingRequests->complete($originalId)?->error(
                    new SnmpAuthenticationException('Peer reported failed authentication')
                );
            } elseif ($varBinds->hasOid(UsmStats::UNKNOWN_USER_NAMES)) {
                $this->outgoingRequests->complete($originalId)?->error(
                    new SnmpAuthenticationException('Peer reported unknown username')
                );
            } elseif ($varBinds->hasOid(UsmStats::DECRYPTION_ERRORS)) {
                $this->outgoingRequests->complete($originalId)?->error(
                    new SnmpAuthenticationException('Peer reported decryption error')
                );
            } elseif ($varBinds->hasOid(UsmStats::NOT_IN_TIME_WINDOWS)) {
                $messageId = $this->reserveMessageId($context);
                $pdu = clone($pdu);
                $pdu->requestId = null;
                $deferred = $this->outgoingRequests->schedulePdu($pdu);
                $this->sendMessage($context->prepareMessage($pdu, $messageId), $context->address);
                delay(0); // TODO: test, whether and how this influences async operation
                try {
                    $responsePdu = $deferred->getFuture()->await();
                } catch (Exception $e) {
                    $this->outgoingRequests->complete($originalId)?->error($e);
                    return;
                }
                if ($responsePdu->errorStatus->isError()) {
                    if ($deferred = $this->outgoingRequests->complete($originalId)) {
                        $deferred->error(new RuntimeException('ERROR, PDU has error -> TODO, not auth issue'));
                    }
                } elseif (!$responsePdu instanceof Response) {
                    if ($deferred = $this->outgoingRequests->complete($originalId)) {
                        $deferred->error(new SnmpAuthenticationException('Still failing'));
                    }
                } elseif ($deferred = $this->outgoingRequests->complete($originalId)) {
                    $deferred->complete($responsePdu);
                } // else -> no id
            }
        } elseif ($responsePdu instanceof Response) {
            if ($deferred = $this->outgoingRequests->complete($originalId)) {
                $deferred->complete($responsePdu);
            } // else: we do not have this id
        }
    }
}
