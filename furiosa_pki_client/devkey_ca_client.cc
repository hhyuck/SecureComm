#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <iostream>
#include <memory>
#include <string>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include <grpcpp/grpcpp.h>

#include "furiosa_ca_devkey.grpc.pb.h"
#include "config.h"
#include "devkey_ca_client.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using devkeyca::DevKeyCA;
using devkeyca::SignDevKeyRequest;
using devkeyca::SignDevKeyResponse;
using devkeyca::RetCode;

std::string DevKeyCAClient::SignDevKeyPub(const uint8_t *pubkey, uint8_t pubkey_len) {
    SignDevKeyRequest request;
    SignDevKeyResponse response;
    ClientContext context;

    const uint64_t *pubkey_ptr = reinterpret_cast<const uint64_t *>(pubkey);

    if( pubkey_len%8 != 0 ) {
        return "Invalid pubkey";
    } 

    for(int i=0; i<pubkey_len/8; i++ )
        request.add_devkeypub(pubkey_ptr[i]);

    Status status = stub_->SignDevKey(&context, request, &response);

    if (status.ok()) {
        int sig_size = response.signature_size();
        uint8_t *signature;
        uint64_t *signature_ptr;

        signature = (uint8_t*)malloc(sizeof(uint64_t)*sig_size);
        signature_ptr = reinterpret_cast<uint64_t*>(signature);

        std::cout << "RET CODE : " << response.ret() << std::endl;
        for(int i=0; i<sig_size; i++ )
            signature_ptr[i] = response.signature(i);

        for(int i=0; i<sig_size*8; i++ )
            printf("%02X", signature[i]);
        printf("\n");

        free(signature);
        return "Good";
    } else {
        std::cout << status.error_code() << ": " << status.error_message()
            << std::endl;
        return "RPC failed";
    }
}
