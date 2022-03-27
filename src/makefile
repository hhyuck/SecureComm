CC=gcc
CFLAGS=-g -Wall
LDLAGS_MBED=-lmbedtls -lmbedcrypto
LDLAGS_OPENSSL=-lssl -lcrypto
MBED_PROGS=mbedtls_ec_dh mbedtls_ec_key_gen mbedtls_ec_key_load
OPENSSL_PROGS=openssl_ec_key_gen openssl_ec_key_load openssl_ec_dsa

all: $(MBED_PROGS) $(OPENSSL_PROGS)

mbedtls_ec_dh: mbedtls_ec_dh.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_MBED)

mbedtls_ec_key_gen: mbedtls_ec_key_gen.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_MBED)

mbedtls_ec_key_load: mbedtls_ec_key_load.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_MBED)

openssl_ec_key_gen: openssl_ec_key_gen.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_OPENSSL)

openssl_ec_key_load: openssl_ec_key_load.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_OPENSSL)

openssl_ec_dsa: openssl_ec_dsa.c
	$(CC) -o $@ $@.c $(CFLAGS) $(LDLAGS_OPENSSL)

clean: 
	rm -fr $(MBED_PROGS) $(OPENSSL_PROGS)

