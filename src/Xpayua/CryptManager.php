<?php

declare(strict_types=1);

namespace Paycore\Xpayua;

use phpseclib\Crypt\RSA;

final class CryptManager implements CryptManagerInterface
{
    public const BLOCK_SIZE = 16;

    private string $method = 'AES-128-CBC';
    private ?string $encryptionKey = null;
    private ?string $encryptedAESkey = null;

    public function reset(): void
    {
        $this->encryptionKey = null;
        $this->encryptedAESkey = null;
    }

    public function encrypt(string $data): string
    {
        // reset encryption key on each operation
        $this->generateEncryptionKey();

        $iv = random_bytes(self::BLOCK_SIZE);

        $pad = $iv . $data;

        $cipherResult = openssl_encrypt($pad, $this->method, $this->getEncryptionKey(), OPENSSL_RAW_DATA, $iv);

        if (false === $cipherResult) {
            throw new \RuntimeException('Can not encrypt data.');
        }

        return base64_encode($cipherResult);
    }

    public function decrypt(string $aesKey, string $data, string $privateKey)
    {
        $key = base64_decode($aesKey, true);

        // STEP 3
        $rsa = new RSA();
        $rsa->loadKey($privateKey);
        $rsa->setEncryptionMode(RSA::MODE_OPENSSL);
        $decryptedKey = $rsa->decrypt($key);

        $iv = substr($data, 0, self::BLOCK_SIZE);

        $resultData = openssl_decrypt($data, $this->method, $decryptedKey, 0, $iv);

        if (false === $resultData) {
            throw new \RuntimeException('Can not decrypt data.');
        }

        return substr($resultData, self::BLOCK_SIZE);
    }

    public function getEncryptedAESKey(string $publicKey): string
    {
        if (null === $this->encryptedAESkey) {
            $rsa = new RSA();
            $rsa->loadKey($publicKey);
            $rsa->setEncryptionMode(RSA::MODE_OPENSSL);
            $binaryCryptedKey = $rsa->encrypt($this->getEncryptionKey());

            $this->encryptedAESkey = base64_encode($binaryCryptedKey);
        }

        return $this->encryptedAESkey;
    }

    public function getEncryptionKey(): string
    {
        if (null === $this->encryptionKey) {
            throw new \RuntimeException('Run encrypt to generate key.');
        }

        return $this->encryptionKey;
    }

    public function getSignedKey(string $privateKey): string
    {
        $rsa = new RSA();
        $rsa->loadKey($privateKey);
        $rsa->setHash('sha256');
        $rsa->setEncryptionMode(RSA::MODE_OPENSSL);
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $binaryEncryptedKey = $rsa->sign(base64_decode($this->encryptedAESkey, true));

        return base64_encode($binaryEncryptedKey);
    }

    private function generateEncryptionKey(): void
    {
        $this->encryptionKey = random_bytes(self::BLOCK_SIZE);
    }
}
