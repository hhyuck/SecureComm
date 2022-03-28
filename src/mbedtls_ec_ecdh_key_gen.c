#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h> 
#include <mbedtls/md.h>     


#include "config.h"
static int furiosa_crypto_rand( void *rng_state, unsigned char *output, size_t len )
{
	size_t use_len;
	static int rnd = 7;
	if( rng_state != NULL )
		rng_state  = NULL;
	while( len > 0 )
	{
		use_len = len;
		if( use_len > sizeof(int) )
			use_len = sizeof(int);
		//rnd = 7;
		//rnd++;
		rnd = rand();
		memcpy( output, &rnd, use_len );
		output += use_len;
		len -= use_len;
	}
	return( 0 );
}

void sign_pub_key() {
	mbedtls_pk_context key;
	mbedtls_ecp_keypair *eck;

	int ret, i;
	int fd;
	uint8_t data_buffer[PUB_KEY_SIZE_IN_BYTES*2];
	uint8_t m[PUB_KEY_SIZE_IN_BYTES];

	mbedtls_mpi r, s;
	mbedtls_sha256_context sha_ctx;

	mbedtls_pk_init( &key );
	ret = mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) );
	eck = mbedtls_pk_ec( key );
	ret = mbedtls_ecp_group_load( &eck->grp, (mbedtls_ecp_group_id) MBEDTLS_ECP_DP_SECP256R1 );

	fd = open( CARDKEY_MBED_FILE, O_RDONLY );
	if ( fd  < 0 ) {
		perror( "open");
		return;
	}

	ret = mbedtls_mpi_grow( &eck->d, PRIV_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_grow( &eck->Q.X, PUB_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_grow( &eck->Q.Y, PUB_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_lset( &eck->Q.Z, 1 );

	read(fd, eck->d.p, PRIV_KEY_SIZE_IN_BYTES );
	read(fd, eck->Q.X.p, PUB_KEY_SIZE_IN_BYTES );
	read(fd, eck->Q.Y.p, PUB_KEY_SIZE_IN_BYTES );
	close(fd);

	fd = open( ECDHKEY_PUB_MBED_FILE, O_RDONLY );
	if ( fd  < 0 ) {
		perror( "open");
		return;
	}
	read(fd, data_buffer, PUB_KEY_SIZE_IN_BYTES*2 );
	close(fd);


	mbedtls_mpi_init( &r );
	mbedtls_mpi_init( &s );

	mbedtls_sha256_init(&sha_ctx); 
	printf("sha256 start %s\n", mbedtls_sha256_starts_ret(&sha_ctx, 0) == 0 ? "SUCCESS": "FAIL" ); 
	printf("sha256 update %s\n", mbedtls_sha256_update_ret(&sha_ctx, data_buffer, PUB_KEY_SIZE_IN_BYTES*2) == 0 ? "SUCCESS": "FAIL" );
	printf("sha256 finish %s\n", mbedtls_sha256_finish_ret(&sha_ctx, m) == 0 ? "SUCCESS": "FAIL" );
	printf("Sign %s\n", mbedtls_ecdsa_sign_det(&eck->grp, &r, &s, &eck->d, m, PUB_KEY_SIZE_IN_BYTES, MBEDTLS_MD_SHA256 ) == 0 ? "SUCCESS": "FAIL" );

	fd = open( ECDHKEY_PUB_SIGNED_MBED_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644 );
    if ( fd  < 0 ) {
        perror( "open");
        return;
    }
    write(fd, data_buffer, PUB_KEY_SIZE_IN_BYTES*2 );
	write(fd, r.p, mbedtls_mpi_size(&r) );
	write(fd, s.p, mbedtls_mpi_size(&s) );

	close(fd);
}


int main() {
	mbedtls_pk_context key;
	mbedtls_ecp_keypair *ecp;
	int ret, i;
	int fd;

	mbedtls_pk_init(&key);
	ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) );
	ecp = mbedtls_pk_ec( key );
	ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) MBEDTLS_ECP_DP_SECP256R1, ecp, furiosa_crypto_rand, NULL );

	fd = open( ECDHKEY_MBED_FILE , O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd  < 0 )
		perror( "open");

	//printf( "d size : %zu signed : %d\n", mbedtls_mpi_size(&ecp->d), ecp->d.s ); 
	write(fd, ecp->d.p, mbedtls_mpi_size(&ecp->d) );
	printf("Private key\t: " );
	mbedtls_mpi_write_file( NULL, &ecp->d, 16, stdout );

	//printf( "Q.X size : %zu signed : %d\n", mbedtls_mpi_size(&ecp->Q.X), ecp->Q.X.s ); 
	write(fd, ecp->Q.X.p, mbedtls_mpi_size(&ecp->Q.X) );
	printf("Public key (X)\t: " );
	mbedtls_mpi_write_file( NULL, &ecp->Q.X, 16, stdout );

	//printf( "Q.Y size : %zu signed : %d\n", mbedtls_mpi_size(&ecp->Q.Y), ecp->Q.Y.s ); 
	write(fd, ecp->Q.Y.p, mbedtls_mpi_size(&ecp->Q.Y) );
	printf("Public key (Y)\t: " );
	mbedtls_mpi_write_file( NULL, &ecp->Q.Y, 16, stdout );

	close(fd); 

	fd = open( ECDHKEY_PUB_MBED_FILE , O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd  < 0 )
		perror( "open");

	write(fd, ecp->Q.X.p, mbedtls_mpi_size(&ecp->Q.X) );
	write(fd, ecp->Q.Y.p, mbedtls_mpi_size(&ecp->Q.Y) );

	close(fd); 
	sign_pub_key();
}
