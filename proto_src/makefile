PROTO_HOME=/usr/local/grpc
PROTOC=$(PROTO_HOME)/bin/protoc
PROTOSRC=furiosa_ca_devkey.proto
PROTOC_PLUGIN=$(PROTO_HOME)/bin/grpc_cpp_plugin

all: $(PROTOSRC) 
	$(PROTOC) --cpp_out=. --grpc_out=. --plugin=protoc-gen-grpc=$(PROTOC_PLUGIN) $(PROTOSRC)

clean: 
	rm -fr *.cc *.h

