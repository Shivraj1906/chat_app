CXX ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -Wpedantic

COMMON_SOURCES = message.cpp socket_io.cpp chat_protocol.cpp
CLIENT_SOURCES = client.cpp client_command.cpp $(COMMON_SOURCES)
SERVER_SOURCES = server.cpp client_registry.cpp $(COMMON_SOURCES)

.PHONY: all clean

all: client server

client: $(CLIENT_SOURCES) message.h socket_io.h chat_protocol.h client_command.h
	$(CXX) $(CXXFLAGS) -pthread $(CLIENT_SOURCES) -o $@

server: $(SERVER_SOURCES) message.h socket_io.h chat_protocol.h client_registry.h
	$(CXX) $(CXXFLAGS) -pthread $(SERVER_SOURCES) -o $@

clean:
	rm -f client server
