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

#include "message.h"
#include "socket_io.h"
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
    cerr << "error in connecting to the server" << endl;
    close(fd);
    return -1;
  }

  cout << "Connection established" << endl;
  string str;
  getline(cin, str);

  // build and send the message
  const Message message(MessageType::CLIENT_HELLO, str);
  if (!send_message(fd, message)) {
    cerr << "error sending message" << endl;
    close(fd);
    return -1;
  }

  Message response(MessageType::SERVER_RESPONSE, "");
  if (!receive_message(fd, response)) {
    cerr << "error receiving response" << endl;
    close(fd);
    return -1;
  }
  if (response.type() != MessageType::SERVER_RESPONSE) {
    cerr << "server sent an unexpected message type" << endl;
    close(fd);
    return -1;
  }
  cout << response.payload_size()
       << " bytes received from the server. Message: "
       << response.payload_as_string() << endl;

  close(fd);
  return 0;
}
