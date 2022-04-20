export PKG_CONFIG_PATH=/usr/local/grpc/lib/pkgconfig

CXX=g++
LDLAGS_MBED=-lmbedtls -lmbedcrypto
CPPFLAGS += `pkg-config --cflags protobuf grpc`
CXXFLAGS += -std=c++11 -I../proto_src
LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++ libssl libcrypto` -pthread -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed -ldl 

PROGS=devkey_ca_client

OBJECTS=devkey_ca_client.o furiosa_ca_devkey.grpc.pb.o furiosa_ca_devkey.pb.o  main.o

all: $(PROGS) $(OPENSSL_PROGS)

devkey_ca_client: $(OBJECTS)
	$(CXX) -o $@ $(OBJECTS)  $(LDLAGS_OPENSSL) $(LDFLAGS) 

%.o: %.cc
	$(CXX) -c $< $(CPPFLAGS) $(CXXFLAGS) 

clean: 
	rm -fr *.o $(PROGS)
