# SecureComm

## Required Lib
```
sudo apt install libmbedtls-dev
```

### grpc
```
git clone --recurse-submodules -b v1.45.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc
cd grpc
mkdir -p cmake/build
cd cmake/build
cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DgRPC_SSL_PROVIDER=OpenSSL -DCMAKE_INSTALL_PREFIX=/usr/local/grpc ../..
make -j
sudo make install
```
