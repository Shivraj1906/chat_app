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

using namespace std;

int main() {
  uint16_t portnumber = 5000;
  string server_ip = "127.0.0.1";
  int fd = socket(AF_INET, SOCK_STREAM, 0);

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

  std::cout << "client connected\n";

  char buffer[256];
  recv(client_fd, buffer, 256, 0);

  cout << "client said: " << buffer << endl;

  string message = "This is the response from server...";
  int bytes_sent = send(client_fd, message.data(), message.size() + 1, 0);

  cout << bytes_sent << " bytes sent to the client" << endl;

  close(client_fd);
  close(fd);

  return 0;
}
