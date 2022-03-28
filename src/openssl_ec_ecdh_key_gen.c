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
	const BIGNUM* priv_key_num ;
	const EC_POINT*	pub_key_point;
	const EC_GROUP* ecgrp ;
	BIGNUM *X;
	BIGNUM *Y; 

	int eccgrp; 
	int fd1,fd2;
	int key_size_in_bytes;
	uint8_t *buffer;


	/* ---------------------------------------------------------- *
	 * These function calls initialize openssl for correct work.  *
	 * ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

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

	/* -------------------------------------------------------- *
	 * Create the public/private EC key pair here               *
	 * ---------------------------------------------------------*/
	if (! (EC_KEY_generate_key(myecc)))
		printf("Error generating the ECC key.");

	/* -------------------------------------------------------- *
	 * Now we show how to extract EC-specifics from the key     *
	 * ---------------------------------------------------------*/

	priv_key_num = EC_KEY_get0_private_key(myecc);
	pub_key_point = EC_KEY_get0_public_key(myecc);

	ecgrp = EC_KEY_get0_group(myecc);
	EC_POINT_get_affine_coordinates(ecgrp, pub_key_point, X, Y, NULL );

	fd1 = open( ECHDKEY_OPENSSL_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd1 < 0 )
		perror( "open : ");

	fd2 = open( ECHDKEY_PUB_OPENSSL_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd2 < 0 )
		perror( "open : ");

	key_size_in_bytes = BN_num_bytes(priv_key_num);
	buffer = (uint8_t*) malloc( key_size_in_bytes );
	memset( buffer, 0x00, key_size_in_bytes );
	//BN_bn2bin( priv_key_num, buffer );
	BN_bn2lebinpad( priv_key_num, buffer, key_size_in_bytes );
	write( fd1, buffer, key_size_in_bytes );

	key_size_in_bytes = BN_num_bytes(X);
	buffer = realloc( buffer, key_size_in_bytes );
	memset( buffer, 0x00, key_size_in_bytes );
	//BN_bn2bin( X, buffer );
	BN_bn2lebinpad( X, buffer, key_size_in_bytes );
	write( fd1, buffer, key_size_in_bytes );
	write( fd2, buffer, key_size_in_bytes );

	key_size_in_bytes = BN_num_bytes(Y);
	buffer = realloc( buffer, key_size_in_bytes );
	memset( buffer, 0x00, key_size_in_bytes );
	//BN_bn2bin( Y, buffer );
	BN_bn2lebinpad( Y, buffer, key_size_in_bytes );
	write( fd1, buffer, key_size_in_bytes );
	write( fd2, buffer, key_size_in_bytes );

	free( buffer );
	close(fd1);
	close(fd2);

    /*
	BN_print_fp( stdout, priv_key_num );	
	printf("\n");
	{
		uint8_t scratch[64];
		int ret,i;
		ret = BN_bn2mpi(priv_key_num, scratch);
		for(i=0; i<ret ; i++ ) {
			printf("%02X", scratch[i] );
		}
		printf("\n");
	}
	BN_print_fp( stdout, X );
	printf("\n");
	BN_print_fp( stdout, Y );
	printf("\n");*/

	EC_KEY_free(myecc);
	BN_free( X ) ;
	BN_free( Y ) ;
}

