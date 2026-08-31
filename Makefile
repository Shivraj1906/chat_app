CXX ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -Wpedantic

COMMON_SOURCES = message.cpp socket_io.cpp

.PHONY: all clean

all: client server

client: client.cpp $(COMMON_SOURCES) message.h socket_io.h
	$(CXX) $(CXXFLAGS) client.cpp $(COMMON_SOURCES) -o $@

server: server.cpp $(COMMON_SOURCES) message.h socket_io.h
	$(CXX) $(CXXFLAGS) server.cpp $(COMMON_SOURCES) -o $@

clean:
	rm -f client server
