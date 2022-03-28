#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h> 
#include <sys/types.h>

#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>

#include "config.h"

static int furiosa_crypto_rand( void *rng_state, unsigned char *output, size_t len ) {
    size_t use_len;
    int rnd;
    if( rng_state != NULL )
        rng_state  = NULL;

    srand( (unsigned int) getpid() );

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);
        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }
    return( 0 );
}


int main() {
	mbedtls_pk_context key;
	mbedtls_ecp_keypair *ecp;
    int ret;
	int fd;

	mbedtls_pk_init(&key);
	ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) );
	ecp = mbedtls_pk_ec( key );
	ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) MBEDTLS_ECP_DP_SECP256R1, ecp, furiosa_crypto_rand, NULL );
	
	fd = open( CARDKEY_MBED_FILE , O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd  < 0 )
		perror( "open");

	write(fd, ecp->d.p, mbedtls_mpi_size(&ecp->d) );
    printf("Private key\t: " );
	mbedtls_mpi_write_file( NULL, &ecp->d, 16, stdout );

	write(fd, ecp->Q.X.p, mbedtls_mpi_size(&ecp->Q.X) );
    printf("Public key (X)\t: " );
	mbedtls_mpi_write_file( NULL, &ecp->Q.X, 16, stdout );

	write(fd, ecp->Q.Y.p, mbedtls_mpi_size(&ecp->Q.Y) );
    printf("Public key (Y)\t: " );
	mbedtls_mpi_write_file( NULL, &ecp->Q.Y, 16, stdout );

	close(fd); 

	fd = open( CARDKEY_PUB_MBED_FILE , O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd  < 0 )
		perror( "open");

	write(fd, ecp->Q.X.p, mbedtls_mpi_size(&ecp->Q.X) );
	write(fd, ecp->Q.Y.p, mbedtls_mpi_size(&ecp->Q.Y) );

	close(fd); 
    mbedtls_pk_free( &key );
}
