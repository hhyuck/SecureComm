#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <memory>
#include <string>

#include <grpc/grpc.h>
#include <grpcpp/server_context.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

#include "furiosa_ca_devkey.grpc.pb.h"
#include "furiosa_pki_ca_devkey.h"
#include "devkey_ca_server.h"
#include "config.h"

using grpc::ServerContext;
using grpc::Status;
using devkeyca::DevKeyCA;
using devkeyca::SignDevKeyRequest;
using devkeyca::SignDevKeyResponse;
using devkeyca::RetCode;

DevKeyCAImpl::DevKeyCAImpl() {
    int sign_key_ec_group_id;
    sign_key_ec_group_id = OBJ_txt2nid(ECTYPE_OPENSSL);
    sign_key = EC_KEY_new_by_curve_name(sign_key_ec_group_id);
    EC_KEY_set_asn1_flag(sign_key, OPENSSL_EC_NAMED_CURVE);
}

DevKeyCAImpl::~DevKeyCAImpl() {
    EC_KEY_free(sign_key);
}

Status DevKeyCAImpl::SignDevKey(ServerContext* context, const SignDevKeyRequest* request, 
        SignDevKeyResponse* response) {
    uint8_t signature[128] = {0,}; 
    uint8_t signature_len;
    int ret;
    int pubkey_size;
    uint8_t *devkeypub;
    uint64_t *devkeypub_ptr;

    pubkey_size = request->devkeypub_size();
    devkeypub = (uint8_t*)malloc(sizeof(uint64_t)*pubkey_size);
    devkeypub_ptr = reinterpret_cast<uint64_t*>(devkeypub);
    
    for(int i=0; i<pubkey_size; i++ )
        devkeypub_ptr[i] = request->devkeypub(i);

    printf("Pub Key : ");
    for(int i=0; i<pubkey_size*8; i++)
        printf("%X", devkeypub[i]);
    printf("\n");
    ret = SignDevKeyPub( devkeypub, pubkey_size*8, signature, &signature_len);
    printf("Signature (%d): ", signature_len);
    for(int i=0; i<signature_len; i++)
        printf("%02X", signature[i]);
    printf("\n");

    if (ret==0 || signature_len % 8 != 0) {
        response->set_ret(RetCode::UNKNOWN_ERROR);
    }
    else {
        uint64_t *key_pub_signature = reinterpret_cast<uint64_t*>(signature);
        for(int i=0; i<signature_len/8; i++ )
            response->add_signature(key_pub_signature[i]);
        response->set_ret(RetCode::OK);
    }

    free(devkeypub);
    return Status::OK;
}

int DevKeyCAImpl::InitializeSignCtx() {
    int fd;
    BIGNUM *d, *X, *Y;
    uint8_t priv_key_buffer[PRIV_KEY_SIZE_IN_BYTES];
    uint8_t pub_key_buffer[PUB_KEY_SIZE_IN_BYTES];

    fd = open(PKI_KEY_FILE, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }

    d = BN_new();
    X = BN_new();
    Y = BN_new();

    if (read(fd, priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES) != PRIV_KEY_SIZE_IN_BYTES) {
        perror("read"); 
        BN_free(X);
        BN_free(Y);
        BN_free(d);
        return 0;
    }
    BN_lebin2bn(priv_key_buffer, PRIV_KEY_SIZE_IN_BYTES, d);

    if (read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES) != PUB_KEY_SIZE_IN_BYTES) {
        perror("read");
        BN_free(X);
        BN_free(Y);
        BN_free(d);
        return 0;
    }
    BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, X);

    if (read(fd, pub_key_buffer, PUB_KEY_SIZE_IN_BYTES) != PUB_KEY_SIZE_IN_BYTES) {
        perror("read");
        BN_free(X);
        BN_free(Y);
        BN_free(d);
        return 0;
    }
    BN_lebin2bn(pub_key_buffer, PUB_KEY_SIZE_IN_BYTES, Y);

    EC_KEY_set_private_key(sign_key, d);
    EC_KEY_set_public_key_affine_coordinates(sign_key, X, Y);

    printf("Load EC Key\n");
    printf("Private key\t: ");
    BN_print_fp(stdout, d);
    printf("\n");
    printf("Public key (X)\t: ");
    BN_print_fp(stdout, X);
    printf("\n");
    printf("Public key (Y)\t: ");
    BN_print_fp(stdout, Y);
    printf("\n");

    close(fd);

    BN_free(X);
    BN_free(Y);
    BN_free(d);
    return 1;
}

int DevKeyCAImpl::SignDevKeyPub(uint8_t *devkey_pub, uint8_t devkey_pub_len, uint8_t *signature, uint8_t *signature_len){
    uint8_t hash_code[SHA256_DIGEST_LENGTH]; 
    unsigned int sig_bn_len;

    int ret;

    SHA256_CTX sha_ctx;
    ECDSA_SIG *ec_sig;
    const BIGNUM *sig_bn;

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, devkey_pub, devkey_pub_len);
    SHA256_Final(hash_code, &sha_ctx);
    OPENSSL_cleanse(&sha_ctx, sizeof (sha_ctx));

    printf("HashCode : ");
    for(int i=0; i<SHA256_DIGEST_LENGTH; i++)
        printf("%X", hash_code[i]);
    printf("\n");

    ec_sig = ECDSA_do_sign( hash_code, SHA256_DIGEST_LENGTH, sign_key);
    if (ec_sig == NULL) {
        printf("sign error\n");
        return 0;
    } 

    sig_bn = ECDSA_SIG_get0_r(ec_sig);
    sig_bn_len = BN_num_bytes(sig_bn);
    BN_bn2lebinpad(sig_bn, signature, sig_bn_len);

    *signature_len = sig_bn_len;
    signature += (*signature_len);

    sig_bn = ECDSA_SIG_get0_s(ec_sig);
    sig_bn_len = BN_num_bytes(sig_bn);
    BN_bn2lebinpad(sig_bn, signature, sig_bn_len);

    *signature_len = *signature_len + sig_bn_len;
    signature[*signature_len] = 0;

    ECDSA_SIG_free(ec_sig);
    return 1;
}
