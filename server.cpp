#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h> // protocol utils
#include <stdlib.h>     //other common C utils
#include <string>
#include <sys/socket.h> // socket utils
#include <sys/types.h>  // common types
#include <unistd.h>     // unix api

#include "message.h"
#include "socket_io.h"

using namespace std;

int main() {
  uint16_t portnumber = 5000;
  string server_ip = "127.0.0.1";
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    cerr << "error in creating socket" << endl;
    return -1;
  }

  int reuse_address = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address,
                 sizeof(reuse_address)) == -1) {
    cerr << "error configuring socket" << endl;
    close(fd);
    return -1;
  }

  sockaddr_in server_address{};
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(portnumber);

  if (inet_pton(AF_INET, server_ip.c_str(), &server_address.sin_addr) != 1) {
    cerr << "error in assigning IP address" << endl;
    close(fd);
    exit(-1);
  }

  if (bind(fd, reinterpret_cast<sockaddr *>(&server_address),
           sizeof(server_address)) == -1) {
    cerr << "Error in binding the address" << endl;
    exit(-1);
  }

  listen(fd, 1);

  std::cout << "Waiting for client ...\n";
  int client_fd = accept(fd, nullptr, nullptr);
  if (client_fd == -1) {
    cerr << "error accepting client" << endl;
    close(fd);
    return -1;
  }

  std::cout << "client connected\n";

  Message request(MessageType::CLIENT_HELLO, "");
  if (!receive_message(client_fd, request)) {
    cerr << "error receiving message" << endl;
    close(client_fd);
    close(fd);
    return -1;
  }
  if (request.type() != MessageType::CLIENT_HELLO) {
    cerr << "client sent an unexpected message type" << endl;
    close(client_fd);
    close(fd);
    return -1;
  }
  cout << "client said: " << request.payload_as_string() << endl;

  const Message response(MessageType::SERVER_RESPONSE,
                         "This is the response from server...");
  if (!send_message(client_fd, response)) {
    cerr << "error sending response" << endl;
    close(client_fd);
    close(fd);
    return -1;
  }
  cout << response.payload_size() << " bytes sent to the client" << endl;

  close(client_fd);
  close(fd);

  return 0;
}
