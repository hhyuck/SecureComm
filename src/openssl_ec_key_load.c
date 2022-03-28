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

    fd = open( ECHDKEY_OPENSSL_FILE, O_CREAT | O_RDONLY );
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

    fd = open( ECDHKEY_PUB_MBED_FILE, O_CREAT | O_RDONLY );
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
	
	EC_KEY_free(myecc);
    EC_POINT_free(pub_key_point);
    EC_POINT_free(shared_key);
	BN_free( X ) ;
	BN_free( Y ) ;
	BN_free( d ) ;
}

