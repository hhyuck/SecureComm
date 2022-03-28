#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>

#include "config.h"
static int furiosa_crypto_rand( void *rng_state, unsigned char *output, size_t len ) {
    size_t use_len;
	int rnd;

    while( len > 0 ) {
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


void generate_ec_key_pair( mbedtls_pk_context *key) {
    int ret;

	mbedtls_pk_init(key);
	ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) );
	ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) MBEDTLS_ECP_DP_SECP256K1, mbedtls_pk_ec( *key ), furiosa_crypto_rand, NULL );
}

int main() {
	mbedtls_pk_context	pk_A, pk_B;
	mbedtls_ecp_keypair *ecp_A, *ecp_B;
	mbedtls_ecp_point	shared_key_A, shared_key_B;
	mbedtls_mpi premaster_secret_A, premaster_secret_B;

	generate_ec_key_pair( &pk_A );
	ecp_A = mbedtls_pk_ec( pk_A );

	generate_ec_key_pair( &pk_B );
	ecp_B = mbedtls_pk_ec( pk_B );

	/* Calc in the Side A*/
	mbedtls_ecp_point_init( &shared_key_A );
	mbedtls_ecp_set_zero( &shared_key_A );
	mbedtls_ecp_mul( &ecp_A->grp, &shared_key_A, &ecp_A->d, &ecp_B->Q, NULL, NULL ); 
	mbedtls_mpi_init( &premaster_secret_A );
	mbedtls_mpi_copy( &premaster_secret_A, &shared_key_A.X );


	/* Calc in the Side B*/
	mbedtls_ecp_point_init( &shared_key_B );
	mbedtls_ecp_set_zero( &shared_key_B );
	mbedtls_ecp_mul( &ecp_B->grp, &shared_key_B, &ecp_B->d, &ecp_A->Q, NULL, NULL );
	mbedtls_mpi_init( &premaster_secret_B );
	mbedtls_mpi_copy( &premaster_secret_B, &shared_key_B.X );

	mbedtls_mpi_write_file( NULL, &shared_key_A.X, 16, stdout );
	mbedtls_mpi_write_file( NULL, &shared_key_B.X, 16, stdout );

	printf( "result f comparison(X) : %d\n", mbedtls_mpi_cmp_abs( &premaster_secret_A, &premaster_secret_B ) );
}
