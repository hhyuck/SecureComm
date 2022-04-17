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

int main() { 
    int fd;
    uint8_t data_buffer[PUB_KEY_SIZE_IN_BYTES * 2] = {0,};
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
