#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "config.h"

void aes_gcm_test( uint8_t *keys ) {
    EVP_CIPHER_CTX *ctx;
    char *iv = "abababababab";
    unsigned char output[64] = {0};
    char *input = "GCM Example code!";
    int i = 0;
    int outlen;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL);
    EVP_EncryptInit (ctx, NULL, (const unsigned char *)keys, (const unsigned char *)iv);
    EVP_EncryptUpdate (ctx, NULL, &outlen, NULL, 0);
    EVP_EncryptUpdate (ctx, output, &outlen, input, strlen(input));

    printf("AES GCM TEST\n");
    printf("Input\t: %s\n", input );
    printf("Output\t: " );
    for( i=0; i<strlen(input); i++ ) {
        printf("%02X", output[i] );
    }
    printf( "\n" );
}

void verify_pub_key(char *pub_key_filename, char *signed_pub_key_filename)
{
	EC_KEY *myecc = NULL;
	int fd;
	int nidEcc;
	uint8_t pub_key_buffer[PUB_KEY_SIZE_IN_BYTES];

	uint8_t data_buffer[PUB_KEY_SIZE_IN_BYTES * 2];

	unsigned char m[SHA256_DIGEST_LENGTH];

	int ret;

	BIGNUM *X, *Y, *r, *s;
	SHA256_CTX sha_ctx;

	ECDSA_SIG *ec_sig;

	nidEcc = OBJ_txt2nid(ECTYPE_OPENSSL);
	myecc = EC_KEY_new_by_curve_name(nidEcc);
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

	X = BN_new();
	Y = BN_new();
	r = BN_new();
	s = BN_new();

	//fd = open( CARDKEY_PUB_MBED_FILE, O_RDONLY );
	fd = open(pub_key_filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return;
	}

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X);

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y);

	close(fd);

	printf("LINE %d : %d\n", __LINE__,
	       EC_KEY_set_public_key_affine_coordinates(myecc, X, Y));

	//fd = open( ECDHKEY_PUB_SIGNED_MBED_FILE, O_RDONLY );
	fd = open(signed_pub_key_filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return;
	}
	read(fd, data_buffer, PUB_KEY_SIZE_IN_BYTES * 2);

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, r);

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, s);

	ec_sig = ECDSA_SIG_new();
	printf("LINE %d : %d\n", __LINE__, ECDSA_SIG_set0(ec_sig, r, s));

	close(fd);

	// Generate Hash for signing
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, data_buffer, PUB_KEY_SIZE_IN_BYTES * 2);
	SHA256_Final(m, &sha_ctx);
	OPENSSL_cleanse(&sha_ctx, sizeof (sha_ctx));

	ret = ECDSA_do_verify(m, SHA256_DIGEST_LENGTH, ec_sig, myecc);

	BN_free(X);
	BN_free(Y);
	ECDSA_SIG_free(ec_sig);	// this frees r and s

	if (ret == 0) {
		printf("Verfification failed\n");
	}
    else {
	    printf("Verfification success\n");
    }
}

int main()
{
	EC_KEY *myecc = NULL;
	EC_POINT *pub_key_point;
	EC_POINT *shared_key;
	const EC_GROUP *ecgrp;
	BIGNUM *d, *X, *Y;
	//HMAC_CTX *hmac_ctx;

	int eccgrp;
	int fd;
	//int key_size_in_bytes;

	uint8_t priv_key_buffer[PRIV_KEY_SIZE_IN_BYTES];
	uint8_t pub_key_buffer[PUB_KEY_SIZE_IN_BYTES];

	uint8_t master_secret[64];
	uint8_t keys[64];
	uint8_t seed[128];
	unsigned int md_len;
	int i;

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

	fd = open(ECHDKEY_OPENSSL_FILE, O_RDONLY);
	if (fd < 0)
		perror("open");

	read(fd, priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES, d);
	printf("LINE %d : %d\n", __LINE__, EC_KEY_set_private_key(myecc, d));

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X);

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y);

	printf("LINE %d : %d\n", __LINE__,
	       EC_KEY_set_public_key_affine_coordinates(myecc, X, Y));

	close(fd);

	fd = open(ECDHKEY_PUB_MBED_FILE, O_RDONLY);
	if (fd < 0)
		perror("open");

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X);

	read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y);

	pub_key_point = EC_POINT_new(ecgrp);
	printf("LINE %d : %d\n", __LINE__,
	       EC_POINT_set_affine_coordinates(ecgrp, pub_key_point, X, Y,
					       NULL));

	close(fd);

	shared_key = EC_POINT_new(ecgrp);
	printf("LINE %d : %d\n", __LINE__,
	       EC_POINT_mul(ecgrp, shared_key, NULL, pub_key_point, d, NULL));

	printf("LINE %d : %d\n", __LINE__,
	       EC_POINT_get_affine_coordinates(ecgrp, shared_key, X, Y, NULL));

	printf("premaster secret : ");
	BN_print_fp(stdout, X);
	printf("\n");

	verify_pub_key(CARDKEY_PUB_MBED_FILE, ECDHKEY_PUB_SIGNED_MBED_FILE);
	verify_pub_key(PKI_KEY_PUB_FILE, CARDKEY_PUB_SIGNED_MBED_FILE);

	memset(master_secret, 0x00, 64);
	memset(seed, 0x00, 128);
	memset(pub_key_buffer, 0x00, PUB_KEY_SIZE_IN_BYTES);

	//hmac_ctx = HMAC_CTX_new();
	BN_bn2lebinpad(X, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES);
	/*
	   for(i=0;i<PUB_KEY_SIZE_IN_BYTES;i++) {
	   printf( "%02X", pub_key_buffer[i] );
	   }
	   printf("\n"); */

	/*
	   printf("LINE %d : %d\n", __LINE__, HMAC_Init_ex( hmac_ctx, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, EVP_sha256(), NULL ));
	   printf("LINE %d : %d\n", __LINE__, HMAC_Update( hmac_ctx, MASTER_SECRET_SEED, strlen(MASTER_SECRET_SEED)));
	   printf("LINE %d : %d\n", __LINE__, HMAC_Final( hmac_ctx, master_secret, &md_len));

	   printf("master secret : ");
	   for(i=0;i<md_len;i++) {
	   printf( "%02X", master_secret[i] );
	   }
	   printf("\n"); */

	HMAC(EVP_sha256(), pub_key_buffer, PUB_KEY_SIZE_IN_BYTES,
	     (unsigned char *)MASTER_SECRET_SEED, strlen(MASTER_SECRET_SEED),
	     master_secret, &md_len);

	/*
	   for(i=0;i<md_len;i++) {
	   printf( "%02X", master_secret[i] );
	   }
	   printf("\n"); */

	memset(seed, 0x00, 128);
	memcpy(seed, master_secret, 32);
	memcpy(seed + 32, &MASTER_SECRET_SEED[0], strlen(MASTER_SECRET_SEED));

	HMAC(EVP_sha256(), pub_key_buffer, PUB_KEY_SIZE_IN_BYTES,
	     (unsigned char *)seed, strlen((char *)seed), master_secret + 32,
	     &md_len);

	printf("master secret : ");
	for (i = 0; i < 48; i++) {
		printf("%02X", master_secret[i]);
	}
	printf("\n");

	HMAC(EVP_sha256(), master_secret, 48,
	     (unsigned char *)KEY_EXPANSION_SEED, strlen(KEY_EXPANSION_SEED),
	     keys, &md_len);

	memset(seed, 0x00, 128);
	memcpy(seed, keys, 32);
	memcpy(seed + 32, &KEY_EXPANSION_SEED[0], strlen(KEY_EXPANSION_SEED));

	HMAC(EVP_sha256(), master_secret, 48,
	     (unsigned char *)seed, strlen((char *)seed), keys + 32, &md_len);

	printf("key for host-write\t: ");
	for (i = 0; i < 32; i++) {
		printf("%02X", keys[i]);
	}
	printf("\n");
	printf("key for device-write\t: ");
	for (i = 32; i < 64; i++) {
		printf("%02X", keys[i]);
	}
	printf("\n");

    aes_gcm_test(keys);

	EC_KEY_free(myecc);
	EC_POINT_free(pub_key_point);
	EC_POINT_free(shared_key);
	BN_free(X);
	BN_free(Y);
	BN_free(d);
}
