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

class DevKeyCAImpl final : public DevKeyCA::Service {
    public:

        explicit DevKeyCAImpl(const std::string& ca_key_priv) {
        }

        Status SignDevKey(ServerContext* context, const SignDevKeyRequest* request, 
            SignDevKeyResponse* response) override{
            std::string key_pub_signature;
            key_pub_signature = "signature";
            response->set_signature(key_pub_signature);
            response->set_ret(RetCode::OK);
            return Status::OK;
        }

    private:
};

void RunServer() {
    std::string server_address("0.0.0.0:50051");
    std::string ca_keypriv_file("key_priv");
    DevKeyCAImpl service(ca_keypriv_file);

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

int main(int argc, char** argv) {
    int ret;

    initialize_openssl();

    ret = check_key_files();
    if( ret == 0 ) {
        ret = generate_pki_ca_devkey();
        if( ret != 0 ) { 
            std::cout << "Error in staring dev key server... " << std::endl;
            return 0;
        }
    } 
    RunServer();
    return 0;
}
