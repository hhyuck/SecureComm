#ifndef __CONFIG__H___
#define __CONFIG__H___

#define CARDKEY_MBED_FILE "card_key_mbed.bin"
#define CARDKEY_PUB_MBED_FILE "card_key_mbed_pub.bin"
#define CARDKEY_PUB_SIGNED_MBED_FILE "card_key_signed_mbed_pub.bin"

#define ECDHKEY_MBED_FILE "card_ecdh_key_mbed.bin"
#define ECDHKEY_PUB_MBED_FILE "card_ecdh_key_mbed_pub.bin"
#define ECDHKEY_PUB_SIGNED_MBED_FILE "card_ecdh_key_signed_mbed_pub.bin"

#define PKI_KEY_FILE "pki_root_key_openssl.bin"
#define PKI_KEY_PUB_FILE "pki_root_key_openssl_pub.bin"

#define ECHDKEY_OPENSSL_FILE "host_ecdh_key_openssl.bin"
#define ECHDKEY_PUB_OPENSSL_FILE "host_ecdh_key_openssl_pub.bin"

#define PRIV_KEY_SIZE_IN_BYTES	32
#define PUB_KEY_SIZE_IN_BYTES	32
#define ECTYPE_OPENSSL			"prime256v1"

#define CLIENT_SERVER_RAND "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!" /* 64 BYTES */
#define HOST_DEVICE_RAND CLIENT_SERVER_RAND

#define MASTER_SECRET_LABEL "master secret"
#define KEY_EXPANSION_LABEL "key expansion"

#define MASTER_SECRET_SEED "master secretABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!"
#define KEY_EXPANSION_SEED "key expansionABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!"

#endif
