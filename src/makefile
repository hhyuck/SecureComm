CC=gcc
CFLAGS=-g -Wall
LDLAGS_MBED=-lmbedtls -lmbedcrypto
LDLAGS_OPENSSL=-lssl -lcrypto
MBED_PROGS=mbedtls_ec_ecdh_key_gen mbedtls_ec_ecdh_key_load mbedtls_ec_card_key_gen
OPENSSL_PROGS=openssl_ec_ecdh_key_gen openssl_ec_ecdh_key_load openssl_ec_pki_key_gen openssl_ec_pki_sign

all: $(MBED_PROGS) $(OPENSSL_PROGS)

mbedtls_ec_card_key_gen: mbedtls_ec_card_key_gen.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_MBED)

mbedtls_ec_ecdh_key_gen: mbedtls_ec_ecdh_key_gen.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_MBED)

mbedtls_ec_ecdh_key_load: mbedtls_ec_ecdh_key_load.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_MBED)

openssl_ec_ecdh_key_gen: openssl_ec_ecdh_key_gen.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_OPENSSL)

openssl_ec_ecdh_key_load: openssl_ec_ecdh_key_load.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_OPENSSL)

openssl_ec_pki_key_gen: openssl_ec_pki_key_gen.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_OPENSSL)

openssl_ec_pki_sign: openssl_ec_pki_sign.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_OPENSSL)

clean: 
	rm -fr $(MBED_PROGS) $(OPENSSL_PROGS)

