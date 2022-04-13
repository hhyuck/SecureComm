export PKG_CONFIG_PATH=/usr/local/grpc/lib/pkgconfig

CXX=g++
LDLAGS_MBED=-lmbedtls -lmbedcrypto
LDLAGS_OPENSSL=-lssl -lcrypto
CPPFLAGS += `pkg-config --cflags protobuf grpc`
CXXFLAGS += -std=c++11 -I../proto_src
LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++` -pthread -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed -ldl

PROGS=devkey_ca_server

OBJECTS=devkey_ca_server.o furiosa_ca_devkey.grpc.pb.o furiosa_ca_devkey.pb.o

all: $(PROGS) $(OPENSSL_PROGS)

devkey_ca_server: $(OBJECTS)
	$(CXX) -o $@ $(OBJECTS) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(LDLAGS_OPENSSL)

%.o: %.cc
	$(CXX) -c $< $(CPPFLAGS) $(CXXFLAGS) 

clean: 
	rm -fr *.o $(PROGS)
