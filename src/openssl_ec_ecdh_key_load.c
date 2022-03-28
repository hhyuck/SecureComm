#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#include "config.h"
void verify_pub_key( char* pub_key_filename, char* signed_pub_key_filename) {
	EC_KEY            *myecc  = NULL;
	int fd; 
	int nidEcc;
	uint8_t pub_key_buffer[PUB_KEY_SIZE_IN_BYTES];

	uint8_t data_buffer[PUB_KEY_SIZE_IN_BYTES*2];
	uint8_t digest[PUB_KEY_SIZE_IN_BYTES*2];

	unsigned char   m[SHA256_DIGEST_LENGTH];

	int ret;

	BIGNUM *X, *Y, *r, *s;
	SHA256_CTX      sha_ctx;

	ECDSA_SIG *ec_sig;

	nidEcc = OBJ_txt2nid( ECTYPE_OPENSSL );
	myecc = EC_KEY_new_by_curve_name(nidEcc);
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

	X = BN_new();
	Y = BN_new();
	r = BN_new();
	s = BN_new();

	//fd = open( CARDKEY_PUB_MBED_FILE, O_RDONLY );
	fd = open( pub_key_filename, O_RDONLY );
    if ( fd  < 0 ) {
        perror( "open");
		return ;
	}

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X );

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y );

	close(fd);

    printf("LINE %d : %d\n", __LINE__, EC_KEY_set_public_key_affine_coordinates( myecc, X, Y ));

	//fd = open( ECDHKEY_PUB_SIGNED_MBED_FILE, O_RDONLY );
	fd = open( signed_pub_key_filename, O_RDONLY );
    if ( fd  < 0 ) {
        perror( "open");
		return ;
	}
    read(fd, data_buffer, PUB_KEY_SIZE_IN_BYTES*2 );

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, r );

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, s );

	ec_sig = ECDSA_SIG_new();
    printf("LINE %d : %d\n", __LINE__, ECDSA_SIG_set0( ec_sig, r, s ) );

	close(fd);


    // Generate Hash for signing
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, data_buffer, PUB_KEY_SIZE_IN_BYTES*2);
    SHA256_Final(m, &sha_ctx);
    OPENSSL_cleanse(&sha_ctx, sizeof(sha_ctx));

	ret = ECDSA_do_verify( m, SHA256_DIGEST_LENGTH, ec_sig, myecc);


	BN_free( X ) ;
	BN_free( Y ) ;
	ECDSA_SIG_free( ec_sig ); // this frees r and s

	if ( ret == 0 ) {
		printf("Verfification failed\n");
		exit(0);
	} 
	printf("Verfification success\n");
}

int main() {
	EC_KEY            *myecc  = NULL;
	EC_POINT*	pub_key_point;
	EC_POINT*	shared_key;
	const EC_GROUP* ecgrp ;
	BIGNUM *d, *X, *Y;

	int eccgrp; 
	int fd;
	int key_size_in_bytes;

    uint8_t priv_key_buffer[PRIV_KEY_SIZE_IN_BYTES];
    uint8_t pub_key_buffer[PUB_KEY_SIZE_IN_BYTES];


	/* ---------------------------------------------------------- *
	 * These function calls initialize openssl for correct work.  *
	 * ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	d = BN_new();
	X = BN_new();
	Y = BN_new();

	/* ---------------------------------------------------------- *
	 * Create a EC key sructure, setting the group type from NID  *
	 * ---------------------------------------------------------- */
	eccgrp = OBJ_txt2nid(ECTYPE_OPENSSL);
	myecc = EC_KEY_new_by_curve_name(eccgrp);

	/* -------------------------------------------------------- *
	 * For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
	 * ---------------------------------------------------------*/
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

    ecgrp = EC_KEY_get0_group(myecc);

    fd = open( ECHDKEY_OPENSSL_FILE, O_RDONLY );
    if ( fd  < 0 )
        perror( "open");

    read(fd, priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES, d );
    printf("LINE %d : %d\n", __LINE__, EC_KEY_set_private_key( myecc, d ));

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X );

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y );

    printf("LINE %d : %d\n", __LINE__, EC_KEY_set_public_key_affine_coordinates( myecc, X, Y ));

    close(fd);

    fd = open( ECDHKEY_PUB_MBED_FILE, O_RDONLY );
    if ( fd  < 0 )
        perror( "open");

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X );

    read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES );
    BN_lebin2bn( pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y );

    pub_key_point = EC_POINT_new( ecgrp );
    printf("LINE %d : %d\n", __LINE__, EC_POINT_set_affine_coordinates( ecgrp, pub_key_point, X, Y, NULL ));

    close(fd);

    shared_key = EC_POINT_new( ecgrp );
    printf("LINE %d : %d\n", __LINE__, EC_POINT_mul( ecgrp, shared_key, NULL, pub_key_point, d, NULL ));

    printf("LINE %d : %d\n", __LINE__, EC_POINT_get_affine_coordinates( ecgrp, shared_key, X, Y, NULL ));

    printf("premaster secret : "); BN_print_fp( stdout, X ); printf("\n");

	verify_pub_key(CARDKEY_PUB_MBED_FILE, ECDHKEY_PUB_SIGNED_MBED_FILE);
	verify_pub_key(PKI_KEY_PUB_FILE, CARDKEY_PUB_SIGNED_MBED_FILE);
	
	EC_KEY_free(myecc);
    EC_POINT_free(pub_key_point);
    EC_POINT_free(shared_key);
	BN_free( X ) ;
	BN_free( Y ) ;
	BN_free( d ) ;
}

