#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <stdlib.h>
#include <mbedtls/ecp.h>

#include "config.h"

int main() {
	mbedtls_pk_context key;
	mbedtls_ecp_keypair *eck;
	mbedtls_ecp_point	ecp;
	mbedtls_ecp_point   shared_key;
	mbedtls_mpi premaster_secret;
    int ret, i;
	int fd;

	mbedtls_pk_init( &key );
	ret = mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) );
	eck = mbedtls_pk_ec( key );
	ret = mbedtls_ecp_group_load( &eck->grp, (mbedtls_ecp_group_id) MBEDTLS_ECP_DP_SECP256R1 );
	
	fd = open( ECDHKEY_MBED_FILE , O_CREAT | O_RDONLY );
	if ( fd  < 0 )
		perror( "open");

	ret = mbedtls_mpi_grow( &eck->d, PRIV_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_grow( &eck->Q.X, PUB_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_grow( &eck->Q.Y, PUB_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_lset( &eck->Q.Z, 1 );

	read(fd, eck->d.p, PRIV_KEY_SIZE_IN_BYTES );
	//printf( "%zu %d\n", mbedtls_mpi_size(&eck->d), eck->d.s ); 
	//mbedtls_mpi_write_file( NULL, &eck->d, 16, stdout );

	read(fd, eck->Q.X.p, PUB_KEY_SIZE_IN_BYTES );
	//printf( "%zu\n", mbedtls_mpi_size(&eck->Q.X) ); 
	//mbedtls_mpi_write_file( NULL, &eck->Q.X, 16, stdout );

	read(fd, eck->Q.Y.p, PUB_KEY_SIZE_IN_BYTES );
	//printf( "%zu\n", mbedtls_mpi_size(&eck->Q.Y) ); 
	//mbedtls_mpi_write_file( NULL, &eck->Q.Y, 16, stdout );

	close(fd);

	mbedtls_ecp_point_init( &ecp );
	ret = mbedtls_mpi_grow( &ecp.X, PUB_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_grow( &ecp.Y, PUB_KEY_SIZE_IN_BYTES/sizeof(mbedtls_mpi_uint) );
	ret = mbedtls_mpi_lset( &ecp.Z, 1 );

	
	fd = open( ECHDKEY_PUB_OPENSSL_FILE , O_CREAT | O_RDONLY );
    if ( fd  < 0 )
        perror( "open");

	read(fd, ecp.X.p, PUB_KEY_SIZE_IN_BYTES );
    //printf( "size : %zu signed : %d\n", mbedtls_mpi_size(&ecp.X), ecp.X.s );
	//mbedtls_mpi_write_file( NULL, &ecp.X, 16, stdout );

	read(fd, ecp.Y.p, PUB_KEY_SIZE_IN_BYTES );
    //printf( "size : %zu signed : %d\n", mbedtls_mpi_size(&ecp.Y), ecp.Y.s );
	//mbedtls_mpi_write_file( NULL, &ecp.Y, 16, stdout );
    close(fd);

    /*printf( "LINE %d %d\n", __LINE__, mbedtls_ecp_check_pubkey( &eck->grp, &ecp ));
    printf( "LINE %d %d\n", __LINE__, mbedtls_ecp_check_pubkey( &eck->grp, &eck->Q ));
    printf( "LINE %d %d\n", __LINE__, mbedtls_mpi_cmp_int( &ecp.Z, 1 ) );
    printf( "LINE %d %d\n", __LINE__, mbedtls_mpi_cmp_int( &eck->Q.Z, 1 ) );
    printf( "LINE %d %d %d\n", __LINE__, eck->grp.G.X.p == NULL, eck->grp.G.Y.p == NULL ); */

	mbedtls_ecp_point_init( &shared_key );
	mbedtls_ecp_set_zero( &shared_key );
    printf( "LINE %d %d\n", __LINE__, mbedtls_ecp_mul( &eck->grp, &shared_key, &eck->d, &ecp, NULL, NULL ));
    /*printf( "LINE %d %d\n", __LINE__, mbedtls_ecp_mul( &eck->grp, &shared_key, &eck->d, &ecp, NULL, NULL ));*/

    mbedtls_mpi_init( &premaster_secret );
    mbedtls_mpi_copy( &premaster_secret, &shared_key.X );
	mbedtls_mpi_write_file( "premaster secret : " , &premaster_secret, 16, stdout );
	/*mbedtls_mpi_write_file( NULL, &shared_key.Y, 16, stdout );*/
}
