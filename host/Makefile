# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CXX), $(CXX)"
	oeedger8r ../helloworld.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CFLAGS) host.c
	$(CXX) -g -c $(CFLAGS) helloworld_u.c
	$(CXX) -o helloworld_host helloworld_u.o host.o $(LDFLAGS)

clean:
	rm -f helloworld_host host.o helloworld_u.o helloworld_u.c helloworld_u.h helloworld_args.h
