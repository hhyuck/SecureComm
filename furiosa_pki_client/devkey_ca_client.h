#ifndef __devkey_ca_client_h__
#define __devkey_ca_client_h__

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

using grpc::Channel;
using devkeyca::DevKeyCA;

class DevKeyCAClient {
    public:
        DevKeyCAClient(std::shared_ptr<Channel> channel)
            : stub_(DevKeyCA::NewStub(channel)) {}

        std::string SignDevKeyPub(const uint8_t *pubkey, uint8_t pubkey_len);

    private:
        std::unique_ptr<DevKeyCA::Stub> stub_;
};

#endif
