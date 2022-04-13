#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <memory>
#include <string>

#include <grpc/grpc.h>
#include <grpcpp/server_context.h>

#include "furiosa_ca_devkey.grpc.pb.h"
#include "furiosa_pki_ca_devkey.h"
#include "devkey_ca_server.h"

using grpc::ServerContext;
using grpc::Status;
using devkeyca::DevKeyCA;
using devkeyca::SignDevKeyRequest;
using devkeyca::SignDevKeyResponse;
using devkeyca::RetCode;

DevKeyCAImpl::DevKeyCAImpl() {
}

DevKeyCAImpl::~DevKeyCAImpl() {
}

Status DevKeyCAImpl::SignDevKey(ServerContext* context, const SignDevKeyRequest* request, 
        SignDevKeyResponse* response) {
    std::string key_pub_signature;
    key_pub_signature = "signature";
    response->set_signature(key_pub_signature);
    response->set_ret(RetCode::OK);
    return Status::OK;
}

int DevKeyCAImpl::InitializeSignCtx() {
    return 1;
}

int DevKeyCAImpl::SignDevKeyPub(uint8_t *devkey_pub, uint8_t devkey_pub_len, uint8_t *signature, uint8_t *sig_len){
    return 1;
}
