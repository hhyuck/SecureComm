#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "furiosa_ca_devkey.grpc.pb.h"

#ifndef __devkey_ca_server__
#define __devkey_ca_server__

/*using devkeyca::DevKeyCA;
using devkeyca::SignDevKeyRequest;
using devkeyca::SignDevKeyResponse;
using devkeyca::RetCode;*/

class DevKeyCAImpl final : public devkeyca::DevKeyCA::Service {
    public:

        explicit DevKeyCAImpl(const std::string& ca_key_priv) {
        }

        grpc::Status SignDevKey(grpc::ServerContext* context, const devkeyca::SignDevKeyRequest* request, 
            devkeyca::SignDevKeyResponse* response) override;

        int InitializeSignCtx() {
            return 1;
        }
            
    private:
};

#endif
