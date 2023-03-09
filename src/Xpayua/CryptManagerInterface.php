<?php

declare(strict_types=1);

namespace Paycore\Xpayua;

interface CryptManagerInterface
{
    public function reset(): void;

    public function encrypt(string $data): string;

    public function decrypt(string $aesKey, string $data, string $privateKey);

    public function getEncryptedAESKey(string $publicKey): string;

    public function getEncryptionKey(): string;

    public function getSignedKey(string $privateKey): string;

}
