#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "key_exchange.h"
#include "pki.h"
#include "secure_channel.h"
#include "socket_io.h"

namespace {

bool parse_port(const char *text, std::uint16_t &port) {
  char *end = nullptr;
  const long value = std::strtol(text, &end, 10);
  if (end == text || *end != '\0' || value < 1 || value > 65535)
    return false;
  port = static_cast<std::uint16_t>(value);
  return true;
}

int connect_to_server(const std::string &ip, std::uint16_t port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    return -1;

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1 ||
      connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) ==
          -1) {
    close(fd);
    return -1;
  }
  return fd;
}

int create_listener(const std::string &ip, std::uint16_t port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1)
    return -1;

  int reuse_address = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address,
             sizeof(reuse_address));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1 ||
      bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == -1 ||
      listen(fd, 10) == -1) {
    close(fd);
    return -1;
  }
  return fd;
}

// Phase 3 attack attempt. Mallory forwards the genuine certificate, then
// substitutes a different client DH transcript toward the real server. The
// real server signs Mallory's transcript; forwarding that signature to the
// victim must fail because the victim verifies its own transcript.
bool attempt_authenticated_mitm(int victim_fd, int server_fd) {
  Message certificate(MessageType::SERVER_CERTIFICATE, "");
  if (!receive_message(server_fd, certificate) ||
      certificate.type() != MessageType::SERVER_CERTIFICATE ||
      !send_message(victim_fd, certificate))
    return false;

  Message victim_key(MessageType::CLIENT_KEY_EXCHANGE, "");
  if (!receive_message(victim_fd, victim_key) ||
      victim_key.type() != MessageType::CLIENT_KEY_EXCHANGE)
    return false;

  std::vector<std::uint8_t> challenge;
  if (!random_bytes(32, challenge))
    return false;
  const DhKeyPair mallory_keys = dh_generate_key_pair();
  const std::string mallory_payload =
      hex_encode(challenge) + "\n" +
      dh_encode_public_key(mallory_keys.public_key);
  if (!send_message(server_fd,
                    Message(MessageType::CLIENT_KEY_EXCHANGE,
                            mallory_payload)))
    return false;

  Message server_response(MessageType::SERVER_KEY_EXCHANGE, "");
  if (!receive_message(server_fd, server_response) ||
      server_response.type() != MessageType::SERVER_KEY_EXCHANGE ||
      !send_message(victim_fd, server_response))
    return false;

  std::cout << "[MITM] forwarded server signature for a substituted DH "
               "transcript; victim should reject it"
            << std::endl;
  return true;
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc != 5) {
    std::cerr << "Usage: " << argv[0]
              << " <listen-ip> <listen-port> <server-ip> <server-port>\n";
    return 1;
  }

  const std::string listen_ip = argv[1];
  const std::string server_ip = argv[3];
  std::uint16_t listen_port = 0;
  std::uint16_t server_port = 0;
  if (!parse_port(argv[2], listen_port) ||
      !parse_port(argv[4], server_port)) {
    std::cerr << "invalid port\n";
    return 1;
  }

  const int listener = create_listener(listen_ip, listen_port);
  if (listener == -1) {
    std::cerr << "could not start MITM listener\n";
    return 1;
  }
  std::cout << "[MITM] listening on " << listen_ip << ':' << listen_port
            << ", forwarding to " << server_ip << ':' << server_port << '\n';

  while (true) {
    const int victim_fd = accept(listener, nullptr, nullptr);
    if (victim_fd == -1)
      continue;

    const int server_fd = connect_to_server(server_ip, server_port);
    if (server_fd == -1) {
      std::cerr << "[MITM] could not connect to real server\n";
      close(victim_fd);
      continue;
    }

    if (!attempt_authenticated_mitm(victim_fd, server_fd)) {
      std::cerr << "[MITM] key exchange failed\n";
    }

    shutdown(victim_fd, SHUT_RDWR);
    shutdown(server_fd, SHUT_RDWR);
    close(victim_fd);
    close(server_fd);
    std::cout << "[MITM] connection closed\n";
  }
}
