export PKG_CONFIG_PATH=/usr/local/grpc/lib/pkgconfig

CXX=g++
LDLAGS_MBED=-lmbedtls -lmbedcrypto
#LDLAGS_OPENSSL=/usr/lib/x86_64-linux-gnu/libcrypto.a /usr/lib/x86_64-linux-gnu/libssl.a
CPPFLAGS += `pkg-config --cflags protobuf grpc`
CXXFLAGS += -std=c++11 -I../proto_src
LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++ libssl libcrypto` -pthread -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed -ldl 

PROGS=devkey_ca_server

OBJECTS=devkey_ca_server.o furiosa_ca_devkey.grpc.pb.o furiosa_ca_devkey.pb.o furiosa_pki_ca_devkey.o main.o

all: $(PROGS) $(OPENSSL_PROGS)

devkey_ca_server: $(OBJECTS)
	$(CXX) -o $@ $(OBJECTS)  $(LDLAGS_OPENSSL) $(LDFLAGS) 

%.o: %.cc
	$(CXX) -c $< $(CPPFLAGS) $(CXXFLAGS) 

clean: 
	rm -fr *.o $(PROGS)
