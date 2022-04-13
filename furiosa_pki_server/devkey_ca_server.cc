#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <memory>
#include <string>

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "furiosa_ca_devkey.grpc.pb.h"
#include "furiosa_ca_devkey.pb.h"
#include "furiosa_pki_ca_devkey.h"
#include "devkey_ca_server.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;
using grpc::Status;
using devkeyca::DevKeyCA;
using devkeyca::SignDevKeyRequest;
using devkeyca::SignDevKeyResponse;
using devkeyca::RetCode;

Status DevKeyCAImpl::SignDevKey(ServerContext* context, const SignDevKeyRequest* request, 
        SignDevKeyResponse* response) {
    std::string key_pub_signature;
    key_pub_signature = "signature";
    response->set_signature(key_pub_signature);
    response->set_ret(RetCode::OK);
    return Status::OK;
}

