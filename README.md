# Library for Xpay
  
This library aims to perform cryptographic operations for interaction with [XPay](https://xpay.com.ua/).


### Key generation
This command will create 2 files in a current directory. Send a public key to XPayua. **Never share the private-key**.

```
./bin/generate-keys
```

### Usage

```php
$privateKey = ''; // your private key
$publicKey = ''; // key that you've got from XPayua
$manager = new CryptManager($privateKey, $publicKey);


$requestData = ['ID' => ''];

$partner = [
    'PartnerToken' => 'TOKEN', // that you've got from XPayua
    'OperationType' => 12345, // integer id of operation
];
        
$data = [
      'Partner' => $partner,
      'Data' => $cryptManager->encrypt($requestData),
      'KeyAES' => $cryptManager->getEncryptedAESKey(),
      'Sign' => $cryptManager->getSignedKey(),
];
```
