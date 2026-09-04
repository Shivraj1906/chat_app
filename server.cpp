#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <pthread.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "chat_protocol.h"
#include "client_registry.h"
#include "key_exchange.h"
#include "pki.h"
#include "secure_channel.h"
#include "socket_io.h"

namespace {

struct ClientContext {
  int fd;
  ClientRegistry *registry;
  const std::vector<std::uint8_t> *certificate;
  const std::string *private_key_path;
};

void log_line(const std::string &level, const std::string &text) {
  static std::mutex log_mutex;
  std::lock_guard<std::mutex> lock(log_mutex);
  std::cout << "[" << level << "] " << text << std::endl;
}

void relay_direct_message(ClientRegistry &registry,
                          const std::string &source_username,
                          const Message &message) {
  chat_protocol::DirectMessage direct;
  if (!chat_protocol::parse_direct_message(message, direct)) {
    registry.send_to(source_username,
                     chat_protocol::server_error("invalid message format"));
    return;
  }

  if (!registry.send_to(
          direct.recipient,
          chat_protocol::delivered_message(source_username, direct.text))) {
    registry.send_to(
        source_username,
        chat_protocol::server_error(direct.recipient + " is not online"));
    return;
  }

  log_line("CHAT", source_username + " -> " + direct.recipient);
}

void *handle_client(void *argument) {
  std::unique_ptr<ClientContext> context(
      static_cast<ClientContext *>(argument));
  const int client_fd = context->fd;
  ClientRegistry &registry = *context->registry;

  if (!send_message(client_fd,
                    Message(MessageType::SERVER_CERTIFICATE,
                            context->certificate->data(),
                            context->certificate->size()))) {
    close(client_fd);
    return nullptr;
  }

  Message client_key_message(MessageType::CLIENT_KEY_EXCHANGE, "");
  if (!receive_message(client_fd, client_key_message) ||
      client_key_message.type() != MessageType::CLIENT_KEY_EXCHANGE) {
    log_line("WARN", "connection closed before Diffie-Hellman exchange");
    close(client_fd);
    return nullptr;
  }

  SessionKey session_key{};
  try {
    const std::string client_payload = client_key_message.payload_as_string();
    const std::size_t separator = client_payload.find('\n');
    if (separator != 64)
      throw std::invalid_argument("invalid client handshake payload");
    std::vector<std::uint8_t> challenge;
    if (!hex_decode(client_payload.substr(0, separator), challenge) ||
        challenge.size() != 32)
      throw std::invalid_argument("invalid client challenge");
    const Number client_public_key =
        dh_decode_public_key(client_payload.substr(separator + 1));
    const DhKeyPair dh_keys = dh_generate_key_pair();
    const std::string server_payload =
        dh_encode_public_key(dh_keys.public_key);
    const std::string signed_text = client_payload + "\n" + server_payload;
    std::vector<std::uint8_t> signature;
    if (!sign_handshake_value(*context->private_key_path,
                              std::vector<std::uint8_t>(
                                  signed_text.begin(), signed_text.end()),
                              signature))
      throw std::runtime_error("could not sign DH transcript");
    const std::string response = server_payload + "\n" + hex_encode(signature);
    if (!send_message(client_fd,
                      Message(MessageType::SERVER_KEY_EXCHANGE, response))) {
      close(client_fd);
      return nullptr;
    }
    const Number shared_secret =
        dh_shared_secret(client_public_key, dh_keys.private_key);
    if (!derive_session_key(shared_secret, session_key))
      throw std::runtime_error("could not derive AES session key");
    log_line("INFO", "secure channel established with RFC 3526 group 14, "
                     "HKDF-SHA256 and AES-256-GCM");
  } catch (const std::exception &error) {
    log_line("WARN", std::string("Diffie-Hellman exchange failed: ") +
                         error.what());
    close(client_fd);
    return nullptr;
  }

  Message hello(MessageType::CLIENT_HELLO, "");
  if (!receive_secure_message(client_fd, hello, session_key) ||
      hello.type() != MessageType::CLIENT_HELLO) {
    log_line("WARN", "connection closed before login");
    close(client_fd);
    return nullptr;
  }

  const std::string username = hello.payload_as_string();
  std::string login_error;
  if (!registry.register_client(username, client_fd, session_key,
                                chat_protocol::login_accepted(),
                                login_error)) {
    if (!login_error.empty()) {
      send_secure_message(client_fd, chat_protocol::login_rejected(login_error),
                          session_key);
      log_line("WARN",
               "login rejected for '" + username + "': " + login_error);
    }
    close(client_fd);
    return nullptr;
  }

  log_line("INFO", username + " connected");
  Message incoming(MessageType::CHAT_MESSAGE, "");

  while (receive_secure_message(client_fd, incoming, session_key)) {
    switch (incoming.type()) {
    case MessageType::DIRECT_MESSAGE:
      relay_direct_message(registry, username, incoming);
      break;
    case MessageType::WHO_REQUEST:
      registry.send_to(
          username,
          chat_protocol::who_response(registry.online_users()));
      break;
    default:
      break;
    }
  }

  registry.remove(username, client_fd);
  close(client_fd);
  log_line("INFO", username + " disconnected");
  return nullptr;
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc > 5) {
    std::cerr << "Usage: " << argv[0]
              << " [port] [bind-ip] [certificate] [private-key]"
              << std::endl;
    return -1;
  }

  const long requested_port = argc >= 2 ? std::strtol(argv[1], nullptr, 10)
                                        : 5000;
  if (requested_port < 1 || requested_port > 65535) {
    std::cerr << "invalid port" << std::endl;
    return -1;
  }
  const std::uint16_t port = static_cast<std::uint16_t>(requested_port);
  const std::string server_ip = argc >= 3 ? argv[2] : "127.0.0.1";
  std::vector<std::uint8_t> certificate;
  const std::string certificate_path = argc >= 4 ? argv[3] : "pki/server.crt";
  const std::string private_key_path = argc >= 5 ? argv[4] : "pki/server.key";
  if (!read_binary_file(certificate_path, certificate)) {
    log_line("ERROR", "could not read server certificate: " + certificate_path);
    return -1;
  }

  const int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    log_line("ERROR", "could not create socket");
    return -1;
  }

  int reuse_address = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address,
             sizeof(reuse_address));

  sockaddr_in server_address{};
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(port);

  if (inet_pton(AF_INET, server_ip.c_str(), &server_address.sin_addr) != 1 ||
      bind(server_fd, reinterpret_cast<sockaddr *>(&server_address),
           sizeof(server_address)) == -1 ||
      listen(server_fd, 10) == -1) {
    log_line("ERROR", "could not start server");
    close(server_fd);
    return -1;
  }

  log_line("INFO", "server listening on " + server_ip + ":" +
                       std::to_string(port));
  ClientRegistry registry;

  while (true) {
    const int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd == -1) {
      continue;
    }

    pthread_t thread;
    ClientContext *context =
        new ClientContext{client_fd, &registry, &certificate,
                          &private_key_path};
    if (pthread_create(&thread, nullptr, handle_client, context) != 0) {
      delete context;
      close(client_fd);
      log_line("ERROR", "could not create client thread");
      continue;
    }
    pthread_detach(thread);
  }
}
