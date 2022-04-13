
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

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using devkeyca::DevKeyCA;
using devkeyca::SignDevKeyRequest;
using devkeyca::SignDevKeyResponse;
using devkeyca::RetCode;

class DevKeyCAClient {
    public:
        DevKeyCAClient(std::shared_ptr<Channel> channel)
            : stub_(DevKeyCA::NewStub(channel)) {}

        std::string SignDevKeyPub(const uint8_t *pubkey, uint8_t pubkey_len) {
            SignDevKeyRequest request;
            SignDevKeyResponse response;
            ClientContext context;

            std::string pubkey_str = (char*)pubkey;
            std::string signature_str; 

            const uint64_t *pubkey_ptr = (const uint64_t *)pubkey;

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
                signature_ptr = (uint64_t*) signature;

                std::cout << "RET CODE : " << response.ret() << std::endl;
                for(int i=0; i<sig_size; i++ )
                   signature_ptr[i] = response.signature(i);

                for(int i=0; i<64; i++ )
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

    private:
        std::unique_ptr<DevKeyCA::Stub> stub_;
};


int main() { 
    int fd;
    uint8_t data_buffer[PUB_KEY_SIZE_IN_BYTES * 2 + 1] = {0,};
    std::string target_str;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    fd = open(CARDKEY_PUB_MBED_FILE, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    read(fd, data_buffer, PUB_KEY_SIZE_IN_BYTES * 2);
    close(fd);

    for(int i=0; i<PUB_KEY_SIZE_IN_BYTES*2; i++ )
        printf("%X", data_buffer[i] );
    printf("\n");
    target_str = "localhost:50051";

    DevKeyCAClient client(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));
    std::string reply = client.SignDevKeyPub(data_buffer, PUB_KEY_SIZE_IN_BYTES * 2);
    std::cout << "Greeter received: " << reply << std::endl;

    return 0;
}
