# Message Encryption in Java

## Intro
- `KeyGeneratorHelper.java` will generate RSA key files: public.key and private.key
- `CryptoHelper.java` will encrypt and decrypt message with RSA and AES keys

## Encryption / Decryption Steps
Server side:
1. Generate a symmetric key(eg: AES).
2. Encrypt message with symmetric key.
3. Encrypt symmetric key with RSA.
4. Send the encrypted message and key to client.

Client side:
5. Decrypt the encrypted AES key with RSA.
6. Decrypt message with AES key.
7. Done.

## Reasons why we need to use both RSA and AES
>   The RSA algorithm can only encrypt data that has a maximum byte length of the RSA key length in bits divided with eight minus eleven padding bytes, i.e. number of maximum bytes = key length in bits / 8 - 11.

## Others

### Crypto Algorithms
1. Symmetric algorithms, eg: AES, DES
2. Non-symmetric algorithms, eg: RSA, DSA, ECC
3. Secure Hash algorithms(can be used to signature), eg: MD5, SHA1

### Message communicate between Android and Java will lead to error
The reason is because android and java use different Security Providers.

The solution is to introduce third-party libraries:
`BouncyCastle` for java and `SpongyCastle` for android.

