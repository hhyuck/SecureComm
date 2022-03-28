#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>

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


int main() {
	mbedtls_pk_context key;
	mbedtls_ecp_keypair *ecp;
	mbedtls_ecp_point pt;
    int ret, i;
	int fd;

	mbedtls_pk_init(&key);
	ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) );
	ecp = mbedtls_pk_ec( key );
	ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) MBEDTLS_ECP_DP_SECP256R1, ecp, furiosa_crypto_rand, NULL );
	
	fd = open( ECDHKEY_MBED_FILE , O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd  < 0 )
		perror( "open");

	printf( "d size : %zu signed : %d\n", mbedtls_mpi_size(&ecp->d), ecp->d.s ); 
	write(fd, ecp->d.p, mbedtls_mpi_size(&ecp->d) );
	mbedtls_mpi_write_file( NULL, &ecp->d, 16, stdout );

	printf( "Q.X size : %zu signed : %d\n", mbedtls_mpi_size(&ecp->Q.X), ecp->Q.X.s ); 
	write(fd, ecp->Q.X.p, mbedtls_mpi_size(&ecp->Q.X) );
	mbedtls_mpi_write_file( NULL, &ecp->Q.X, 16, stdout );

	printf( "Q.Y size : %zu signed : %d\n", mbedtls_mpi_size(&ecp->Q.Y), ecp->Q.Y.s ); 
	write(fd, ecp->Q.Y.p, mbedtls_mpi_size(&ecp->Q.Y) );
	mbedtls_mpi_write_file( NULL, &ecp->Q.Y, 16, stdout );

	close(fd); 

	fd = open( ECDHKEY_PUB_MBED_FILE , O_CREAT | O_RDWR | O_TRUNC, 0644 );
	if ( fd  < 0 )
		perror( "open");

	write(fd, ecp->Q.X.p, mbedtls_mpi_size(&ecp->Q.X) );
	write(fd, ecp->Q.Y.p, mbedtls_mpi_size(&ecp->Q.Y) );

	close(fd); 

	/*
	mbedtls_ecp_point_init( &pt );
	mbedtls_ecp_set_zero( &pt );
	mbedtls_ecp_mul( &ecp->grp, &pt, &ecp->d, &ecp->grp.G, NULL, NULL );

	printf( "result of comparison(X) : %d\n", mbedtls_mpi_cmp_abs( &ecp->Q.X, &pt.X) );
	printf( "result of comparison(Y) : %d\n", mbedtls_mpi_cmp_abs( &ecp->Q.Y, &pt.Y) );*/
}
