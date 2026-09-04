CXX ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -Wpedantic

COMMON_SOURCES = message.cpp socket_io.cpp chat_protocol.cpp secure_channel.cpp pki.cpp
CLIENT_SOURCES = client.cpp client_command.cpp $(COMMON_SOURCES)
SERVER_SOURCES = server.cpp client_registry.cpp $(COMMON_SOURCES)
PROXY_SOURCES = mitm_proxy.cpp message.cpp socket_io.cpp secure_channel.cpp pki.cpp

.PHONY: all clean

all: client server mitm_proxy

client: $(CLIENT_SOURCES) message.h socket_io.h chat_protocol.h client_command.h key_exchange.h pki.h
	$(CXX) $(CXXFLAGS) -pthread $(CLIENT_SOURCES) -lcrypto -o $@

server: $(SERVER_SOURCES) message.h socket_io.h chat_protocol.h client_registry.h key_exchange.h pki.h
	$(CXX) $(CXXFLAGS) -pthread $(SERVER_SOURCES) -lcrypto -o $@

mitm_proxy: $(PROXY_SOURCES) message.h socket_io.h secure_channel.h key_exchange.h pki.h
	$(CXX) $(CXXFLAGS) $(PROXY_SOURCES) -lcrypto -o $@

clean:
	rm -f client server mitm_proxy
