<?php

namespace IMEdge\SnmpClient\Usm;

use Amp\Socket\InternetAddress;
use FreeDSx\Asn1\Encoder\BerEncoder;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use IMEdge\SnmpClient\SnmpCredential;
use IMEdge\SnmpPacket\Error\SnmpAuthenticationException;
use IMEdge\SnmpPacket\Message\VarBindList;
use IMEdge\SnmpPacket\ParseHelper;
use IMEdge\SnmpPacket\Pdu\GetRequest;
use IMEdge\SnmpPacket\Pdu\Pdu;
use IMEdge\SnmpPacket\Pdu\Report;
use IMEdge\SnmpPacket\Message\SnmpMessage;
use IMEdge\SnmpPacket\SnmpSecurityLevel;
use IMEdge\SnmpPacket\Message\SnmpV1Message;
use IMEdge\SnmpPacket\Message\SnmpV2Message;
use IMEdge\SnmpPacket\Message\SnmpV3Header;
use IMEdge\SnmpPacket\Message\SnmpV3Message;
use IMEdge\SnmpPacket\Message\SnmpV3ScopedPdu;
use IMEdge\SnmpPacket\SnmpVersion;
use IMEdge\SnmpPacket\Usm\AuthenticationModule;
use IMEdge\SnmpPacket\Usm\PrivacyModule;
use IMEdge\SnmpPacket\Usm\RemoteEngine;
use IMEdge\SnmpPacket\Usm\UserBasedSecurityModel;
use IMEdge\SnmpPacket\Usm\UsmStats;
use RuntimeException;

class ClientContext
{
    protected const MAX_LOCAL_ARBITRARY_INTEGER = 2 ** 32 - 1;
    protected static ?BerEncoder $encoder = null;

    public readonly RemoteEngine $engine;
    protected ?AuthenticationModule $authentication = null;
    protected ?PrivacyModule $privacy = null;
    protected int $localArbitraryInteger;

    /**
     * @throws SnmpAuthenticationException
     */
    public function __construct(
        public readonly InternetAddress $address,
        public readonly SnmpCredential $credential
    ) {
        $this->engine = new RemoteEngine();
        $this->refreshAuthenticationModel();
        $this->refreshPrivacyModel();
        $this->localArbitraryInteger = random_int(0, self::MAX_LOCAL_ARBITRARY_INTEGER);
    }

    public function wantsAuthentication(): bool
    {
        return $this->credential->securityLevel?->wantsAuthentication() ?? false;
    }

    public function wantsEncryption(): bool
    {
        return $this->credential->securityLevel?->wantsEncryption() ?? false;
    }

    public function prepareUnauthenticatedMessage(Pdu $pdu, int $messageId): SnmpV3Message
    {
        return new SnmpV3Message(
            new SnmpV3Header(
                messageId: $messageId,
                securityFlags: $this->credential->securityLevel
                ?? throw new SnmpAuthenticationException('Credential w/o security level is not valid'),
                reportableFlag: true,
            ),
            $usm = UserBasedSecurityModel::create(
                $this->credential->securityName ?? '',
                $this->engine,
                $this->getEncryptionSalt()
            ),
            $this->prepareScopedPdu($pdu, $usm->privacyParams)
        );
    }

    /**
     * @throws SnmpAuthenticationException
     */
    public function prepareMessage(Pdu $pdu, ?int $messageId = null): SnmpMessage
    {
        switch ($this->credential->version) {
            case SnmpVersion::v1:
                return new SnmpV1Message(
                    $this->credential->securityName
                    ?? throw new SnmpAuthenticationException('Credential w/o security name is not valid'),
                    $pdu
                );
            case SnmpVersion::v2c:
                return new SnmpV2Message(
                    $this->credential->securityName
                    ?? throw new SnmpAuthenticationException('Credential w/o security name is not valid'),
                    $pdu
                );
            case SnmpVersion::v3:
                if ($messageId === null) {
                    throw new RuntimeException('SNMPv3 requires a messageId');
                }
                if (!$this->privacy && $this->wantsEncryption()) {
                    $pdu = new GetRequest(new VarBindList(), $pdu->requestId);
                    $securityFlags = SnmpSecurityLevel::AUTH_NO_PRIV;
                    // echo "No privacy, but want encryption -> intermediate package\n";
                } else {
                    $securityFlags = $this->credential->securityLevel
                        ?? throw new SnmpAuthenticationException('Credential w/o security level is not valid');
                }
                return $this->authenticateOutgoing(new SnmpV3Message(
                    new SnmpV3Header(
                        messageId: $messageId,
                        securityFlags: $securityFlags,
                        reportableFlag: true,
                    ),
                    $usm = UserBasedSecurityModel::create(
                        $this->credential->securityName ?? '',
                        $this->engine,
                        $this->getEncryptionSalt()
                    ),
                    $this->prepareScopedPdu($pdu, $usm->privacyParams)
                ));
            default:
                throw new RuntimeException('SNMP version is required');
        }
    }

    /**
     * @throws SnmpAuthenticationException
     */
    public function refreshFromSecurityParameters(UserBasedSecurityModel $securityParameters): void
    {
        if ($this->engine->refresh($securityParameters)) {
            $this->refreshAuthenticationModel();
            $this->refreshPrivacyModel();
        }
    }

    /**
     * @throws SnmpAuthenticationException
     */
    protected function authenticateOutgoing(SnmpV3Message $message): SnmpV3Message
    {
        return $this->authentication?->authenticateOutgoingMsg($message) ?? $message;
    }

    protected function getEncryptionSalt(): string
    {
        if ($this->privacy === null) {
            return '';
        }

        if ($this->privacy->privacyProtocol->isDES()) {
            if ($this->localArbitraryInteger === self::MAX_LOCAL_ARBITRARY_INTEGER) {
                $this->localArbitraryInteger = 0;
            } else {
                $this->localArbitraryInteger++;
            }

            return pack('NN', $this->engine->boots, $this->localArbitraryInteger);
        } else {
            // TODO: arbitrary int might suffice?
            return random_bytes(8);
        }
    }

    protected function prepareScopedPdu(Pdu $pdu, string $salt): SnmpV3ScopedPdu
    {
        if ($this->privacy) {
            self::$encoder ??= new BerEncoder();
            return SnmpV3ScopedPdu::encrypted($this->privacy->encrypt(
                (self::$encoder->encode(new SequenceType(
                    new OctetStringType(''), // contextEngineId??
                    new OctetStringType(''), // contextName??
                    $pdu->toAsn1(),
                ))),
                $salt,
            ), $pdu);
        }

        return SnmpV3ScopedPdu::forPdu($pdu, '', '');
    }

    /**
     * @throws SnmpAuthenticationException
     */
    protected function refreshAuthenticationModel(): void
    {
        $credential = $this->credential;
        if ($credential->authProtocol === null || $credential->authKey === null) {
            $this->authentication = null;
        } else {
            $this->authentication = new AuthenticationModule(
                $credential->authKey,
                $this->engine->id,
                $credential->authProtocol
            );
        }
    }

    protected function refreshPrivacyModel(): void
    {
        $credential = $this->credential;
        if (
            $this->engine->id === ''
            || $credential->privProtocol === null
            || $credential->privKey === null
            || $credential->authProtocol === null
        ) {
            $this->privacy = null;
        } else {
            $this->privacy = new PrivacyModule(
                $credential->privKey,
                $this->engine,
                $credential->authProtocol,
                $credential->privProtocol,
            );
        }
    }

    protected function authenticate(SnmpV3Message $message): bool
    {
        if ($this->authentication) {
            return $this->authentication->authenticateIncomingMessage($message);
        }

        throw new SnmpAuthenticationException('Cannot authenticate the given message');
    }

    /**
     * @throws SnmpAuthenticationException
     */
    public function handleIncomingV3Message(SnmpV3Message $message): Pdu|bool
    {
        if (! $this->wantsAuthentication()) {
            // echo "Wants no auth\n";
            return $message->getPdu();
        }

        $usm = $message->securityParameters;
        if (! $usm instanceof UserBasedSecurityModel) {
            throw new SnmpAuthenticationException('USM is required');
        }

        if ($this->authentication === null || !$this->engine->hasId()) {
            $this->refreshFromSecurityParameters($usm);
            return true;
        }

        if (! $this->authenticate($message)) {
            if (($pdu = $message->scopedPdu->pdu) && ($pdu instanceof Report)) {
                throw new SnmpAuthenticationException(
                    UsmStats::getErrorForVarBindList($pdu->varBinds) ?? 'unknown error'
                );
            }
            var_dump('NOT AUTH INCOMING, kein Report-Dings');

            return false;
        }

        if (!$this->wantsEncryption()) {
            if ($message->scopedPdu->isPlainText()) {
                return $message->getPdu();
            } else {
                return false;
            }
        }
        $privacy = $this->privacy;
        if ($privacy === null) {
            $this->refreshFromSecurityParameters($usm);
            return true;
        }

        if ($message->scopedPdu->isPlainText()) {
            return false;
        }
        if ($usm->privacyParams === '') {
            return false;
        }
        if ($message->scopedPdu->encryptedPdu === null) {
            return false;
        }
        $this->refreshFromSecurityParameters($usm);

        try {
            self::$encoder ??= new BerEncoder();
            $binary = $privacy->decrypt($message->scopedPdu->encryptedPdu, $usm->privacyParams);
            $pdu = SnmpV3ScopedPdu::fromAsn1(
                ParseHelper::requireSequence(self::$encoder->decode($binary), 'scopedPdu')
            )->pdu;
        } catch (\Exception $e) {
            // All kind of errors, Unexpected end of data while decoding long form length
            // Decode error: Length 123 overflows data, 68 bytes left.
            // Decode error: SEQUENCE expected, got primitive CONTEXT SPECIFIC TAG 29
            // Integer overflow
            // echo 'Decode error: ' . $e->getMessage() . "\n";
            // echo "Encrypted:\n" . bin2hex($message->scopedPdu->encryptedPdu) . "\n";
            // echo "Decrypted:\n" . bin2hex($binary) . "\n";

            return false;
        }
        if ($pdu === null) {
            throw new RuntimeException('Decrypted, but still no PDU? Logical error, should not happen');
        }

        return $pdu;
    }
}
