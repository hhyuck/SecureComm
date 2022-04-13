#include <grpcpp/server_context.h>

#include <grpc/grpc.h>
#include <grpcpp/server_context.h>

#include "furiosa_ca_devkey.grpc.pb.h"

#ifndef __devkey_ca_server__
#define __devkey_ca_server__

class DevKeyCAImpl final : public devkeyca::DevKeyCA::Service {
    public:
        DevKeyCAImpl();
        ~DevKeyCAImpl();
        int InitializeSignCtx();
        grpc::Status SignDevKey(grpc::ServerContext* context, const devkeyca::SignDevKeyRequest* request, 
            devkeyca::SignDevKeyResponse* response) override;
            
    private:
        int SignDevKeyPub(uint8_t *devkey_pub, uint8_t devkey_pub_len, uint8_t *signature, uint8_t *sig_len);
};

#endif
