#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "config.h"

int main() {
	EC_KEY            *myecc  = NULL;
	const EC_GROUP* ecgrp ;
	BIGNUM *d, *X, *Y;

	int eccgrp; 
	int fd;
	int key_size_in_bytes;

	uint8_t priv_key_buffer[PRIV_KEY_SIZE_IN_BYTES];
	uint8_t pub_key_buffer[PUB_KEY_SIZE_IN_BYTES];

	uint8_t data_buffer[PUB_KEY_SIZE_IN_BYTES*2];

	unsigned char   m[SHA256_DIGEST_LENGTH];

	SHA256_CTX      sha_ctx;
	unsigned char   sig[256];
	unsigned int    lenSig;
	const unsigned char* sigptr;

	ECDSA_SIG* ecSig = NULL;
	uint8_t *buffer;

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	d = BN_new();
	X = BN_new();
	Y = BN_new();

	eccgrp = OBJ_txt2nid(ECTYPE_OPENSSL);

	myecc = EC_KEY_new_by_curve_name(eccgrp);
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);
	ecgrp = EC_KEY_get0_group(myecc);

	fd = open( PKI_KEY_FILE, O_RDONLY );
	if ( fd  < 0 ) {
		perror( "open");
		return fd;
	}

	read(fd, priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES );
	BN_lebin2bn( priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES, d );

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
	BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X );

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
	BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y );

	printf("Read private key %d\n", EC_KEY_set_private_key( myecc, d ));
	printf("Read public key %d\n",  EC_KEY_set_public_key_affine_coordinates( myecc, X, Y ));

	close(fd);

	fd = open( CARDKEY_PUB_MBED_FILE, O_RDONLY );
	if ( fd  < 0 ) {
		perror( "open");
		return fd;
	}
	read(fd, data_buffer, PUB_KEY_SIZE_IN_BYTES*2 );
	close(fd);

	// Generate Hash for signing
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, data_buffer, PUB_KEY_SIZE_IN_BYTES*2);
	SHA256_Final(m, &sha_ctx);
	OPENSSL_cleanse(&sha_ctx, sizeof(sha_ctx));

	printf( "Sign %d\n", ECDSA_sign(0, m, SHA256_DIGEST_LENGTH, sig, &lenSig, myecc));

	sigptr = &sig[0];
	if( d2i_ECDSA_SIG(&ecSig, &sigptr, lenSig) == NULL ) {
		printf("Error\n");
		return fd;
	} 

	fd = open( CARDKEY_PUB_SIGNED_MBED_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd  < 0 ) {
		perror( "open");
		return fd;
	}
	write(fd, data_buffer, PUB_KEY_SIZE_IN_BYTES*2 );

	X = ECDSA_SIG_get0_r( ecSig );
	Y = ECDSA_SIG_get0_s( ecSig );

	key_size_in_bytes = BN_num_bytes(X);
	buffer = (uint8_t*) malloc( key_size_in_bytes );
	memset( buffer, 0x00, key_size_in_bytes );
	BN_bn2lebinpad( X, buffer, key_size_in_bytes );
	write( fd, buffer, key_size_in_bytes );

	key_size_in_bytes = BN_num_bytes(X);
	buffer = (uint8_t*) realloc( buffer, key_size_in_bytes );
	memset( buffer, 0x00, key_size_in_bytes );
	BN_bn2lebinpad( Y, buffer, key_size_in_bytes );
	write( fd, buffer, key_size_in_bytes );

	close(fd);

	//printf( "Verify %d\n", ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, sig, &lenSig, ecKey));
	EC_KEY_free(myecc);
	BN_free( X ) ;
	BN_free( Y ) ;
	BN_free( d ) ;
	free( buffer );
}
