# crypto-tools
Crypto is a CLI tool that prints checksums using the crypto Go package.

### Usage
Print the SHA256 checksum of the text "input_message":

    crypto hash input_message --sha256


Print the SHA512 checksum of the stdin text:

    echo "input_message_from_stdin" | crypto hash --sha512


List supported cryptographic hash functions:

    crypto help hash
    
