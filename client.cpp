#include <arpa/inet.h>
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
  if (fd == -1) {
    cerr << "error in creating socket" << endl;
    exit(-1);
  }
  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(portnumber);

  if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) != 1) {
    cerr << "error in assigning IP address" << endl;
    close(fd);
    exit(-1);
  }

  if (connect(fd, reinterpret_cast<sockaddr *>(&server_addr),
              sizeof(server_addr)) == -1) {
    cout << "error in connecting to the server" << endl;
  }

  cout << "Connection established" << endl;
  string message;
  getline(cin, message);

  long bytes_sent = send(fd, message.data(), message.size() + 1, 0);
  cout << bytes_sent << "bytes sent to the server" << endl;

  // receive a response form the server
  char buffer[256];

  long bytes_received = recv(fd, buffer, 256, 0);
  cout << bytes_received
       << " bytes received from the server. Message: " << buffer << endl;

  close(fd);
  return 0;
}
