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

void initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

int check_key_files() {
    if( access( PKI_KEY_FILE, F_OK ) == -1 ) 
        return 0;
    if( access( PKI_KEY_PUB_FILE, F_OK ) == -1 ) 
        return 0;
    return 1;
}

int generate_pki_ca_devkey() {
    EC_KEY *myecc = NULL;
    const EC_POINT *pub_key_point;
    const EC_GROUP *ecgrp;

    const BIGNUM *d;
    BIGNUM *X;
    BIGNUM *Y;

    int eccgrp;
    int fd1, fd2;
    int key_size_in_bytes;
    uint8_t *buffer;

    eccgrp = OBJ_txt2nid(ECTYPE_OPENSSL);
    myecc = EC_KEY_new_by_curve_name(eccgrp);
    EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

    if (!(EC_KEY_generate_key(myecc))) {
        printf("Error generating the ECC key.");
        return 1;
    }

    fd1 = open(PKI_KEY_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd1 < 0) {
        perror("open : ");
        return 2;
    }

    fd2 = open(PKI_KEY_PUB_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd1 < 0) {
        perror("open : ");
        return 2;
    }

    ecgrp = EC_KEY_get0_group(myecc);
    X = BN_new();
    Y = BN_new();

    d = EC_KEY_get0_private_key(myecc);
    pub_key_point = EC_KEY_get0_public_key(myecc);
    EC_POINT_get_affine_coordinates(ecgrp, pub_key_point, X, Y, NULL);
    
    printf("Generate EC Key\n");
    printf("Private key\t: ");
    BN_print_fp(stdout, d);
    printf("\n");
    printf("Public key (X)\t: ");
    BN_print_fp(stdout, X);
    printf("\n");
    printf("Public key (Y)\t: ");
    BN_print_fp(stdout, Y);
    printf("\n");

    key_size_in_bytes = BN_num_bytes(d);
    buffer = (uint8_t *) malloc(key_size_in_bytes);
    memset(buffer, 0x00, key_size_in_bytes);
    BN_bn2lebinpad(d, buffer, key_size_in_bytes);
    write(fd1, buffer, key_size_in_bytes);

    key_size_in_bytes = BN_num_bytes(X);
    buffer = (uint8_t*)realloc(buffer, key_size_in_bytes);
    memset(buffer, 0x00, key_size_in_bytes);
    BN_bn2lebinpad(X, buffer, key_size_in_bytes);
    write(fd1, buffer, key_size_in_bytes);
    write(fd2, buffer, key_size_in_bytes);

    key_size_in_bytes = BN_num_bytes(Y);
    buffer = (uint8_t*)realloc(buffer, key_size_in_bytes);
    memset(buffer, 0x00, key_size_in_bytes);
    BN_bn2lebinpad(Y, buffer, key_size_in_bytes);
    write(fd1, buffer, key_size_in_bytes);
    write(fd2, buffer, key_size_in_bytes);

    free(buffer);
    close(fd1);
    close(fd2);

    EC_KEY_free(myecc);
    BN_free(X);
    BN_free(Y);
    return 0;
}
