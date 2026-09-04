#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <pthread.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "chat_protocol.h"
#include "client_command.h"
#include "key_exchange.h"
#include "pki.h"
#include "secure_channel.h"
#include "socket_io.h"

using namespace std;

pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ReceiveContext {
  int fd;
  const SessionKey *key;
};

void print_prompt() {
  pthread_mutex_lock(&output_mutex);
  cout << "> " << flush;
  pthread_mutex_unlock(&output_mutex);
}

void *receive_messages(void *argument) {
  const ReceiveContext &context = *static_cast<ReceiveContext *>(argument);
  const int fd = context.fd;
  Message message(MessageType::CHAT_MESSAGE, "");

  while (receive_secure_message(fd, message, *context.key)) {
    pthread_mutex_lock(&output_mutex);
    cout << '\r';
    if (message.type() == MessageType::SERVER_ERROR) {
      cerr << "[ERROR] " << message.payload_as_string() << endl;
    } else if (message.type() == MessageType::WHO_RESPONSE) {
      cout << "Online users: " << message.payload_as_string() << endl;
    } else if (message.type() == MessageType::CHAT_MESSAGE) {
      cout << message.payload_as_string() << endl;
    }
    cout << "> " << flush;
    pthread_mutex_unlock(&output_mutex);
  }

  return nullptr;
}

void print_command_guide() {
  cout << "\nCommands:\n"
       << "  @<username> <message>  Send a message and select that user\n"
       << "  /chat <username>       Select a chat partner\n"
       << "  /who                   List online users\n"
       << "  /quit                  Disconnect and exit\n"
       << endl;
}

int main(int argc, char *argv[]) {
  if (argc != 4 && argc != 5) {
    cerr << "Usage: " << argv[0]
         << " <server-ip> <port> <username> [ca-certificate]" << endl;
    return -1;
  }

  const string server_ip = argv[1];
  const long port = strtol(argv[2], nullptr, 10);
  const string username = argv[3];
  if (port < 1 || port > 65535) {
    cerr << "invalid port" << endl;
    return -1;
  }

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    cerr << "error in creating socket" << endl;
    return -1;
  }

  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(static_cast<uint16_t>(port));

  if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) != 1) {
    cerr << "error in assigning IP address" << endl;
    close(fd);
    return -1;
  }

  if (connect(fd, reinterpret_cast<sockaddr *>(&server_addr),
              sizeof(server_addr)) == -1) {
    cerr << "error in connecting to the server" << endl;
    close(fd);
    return -1;
  }

  const string ca_certificate_path = argc == 5 ? argv[4] : "pki/ca.crt";
  Message certificate_message(MessageType::SERVER_CERTIFICATE, "");
  if (!receive_message(fd, certificate_message) ||
      certificate_message.type() != MessageType::SERVER_CERTIFICATE ||
      !verify_server_certificate(
          std::vector<std::uint8_t>(certificate_message.payload_data(),
                                    certificate_message.payload_data() +
                                        certificate_message.payload_size()),
          ca_certificate_path, server_ip)) {
    cerr << "server certificate validation failed" << endl;
    close(fd);
    return -1;
  }

  const DhKeyPair dh_keys = dh_generate_key_pair();
  vector<uint8_t> challenge;
  if (!random_bytes(32, challenge)) {
    cerr << "error generating handshake challenge" << endl;
    close(fd);
    return -1;
  }
  const string client_key_payload =
      hex_encode(challenge) + "\n" + dh_encode_public_key(dh_keys.public_key);
  if (!send_message(fd,
                    Message(MessageType::CLIENT_KEY_EXCHANGE,
                            client_key_payload))) {
    cerr << "error sending authenticated DH exchange" << endl;
    close(fd);
    return -1;
  }

  Message server_key_message(MessageType::SERVER_KEY_EXCHANGE, "");
  if (!receive_message(fd, server_key_message) ||
      server_key_message.type() != MessageType::SERVER_KEY_EXCHANGE) {
    cerr << "error receiving authenticated DH exchange" << endl;
    close(fd);
    return -1;
  }

  Number shared_secret;
  try {
    const string response = server_key_message.payload_as_string();
    const size_t separator = response.rfind('\n');
    if (separator == string::npos)
      throw invalid_argument("invalid server handshake payload");
    const string server_key_payload = response.substr(0, separator);
    vector<uint8_t> signature;
    if (!hex_decode(response.substr(separator + 1), signature))
      throw invalid_argument("invalid server handshake signature");
    const string signed_text = client_key_payload + "\n" + server_key_payload;
    const vector<uint8_t> signed_bytes(signed_text.begin(), signed_text.end());
    const vector<uint8_t> certificate(
        certificate_message.payload_data(),
        certificate_message.payload_data() + certificate_message.payload_size());
    if (!verify_handshake_signature(certificate, signed_bytes, signature))
      throw invalid_argument("server proof-of-possession failed");
    shared_secret = dh_shared_secret(
        dh_decode_public_key(server_key_payload),
        dh_keys.private_key);
  } catch (const std::exception &error) {
    cerr << "Diffie-Hellman exchange failed: " << error.what() << endl;
    close(fd);
    return -1;
  }
  SessionKey session_key{};
  if (!derive_session_key(shared_secret, session_key)) {
    cerr << "failed to derive AES session key" << endl;
    close(fd);
    return -1;
  }
  cout << "Server certificate validated; proof-of-possession verified; "
          "secure channel established with RFC 3526 group 14, HKDF-SHA256 "
          "and AES-256-GCM"
       << endl;

  if (!send_secure_message(fd, chat_protocol::login_request(username),
                           session_key)) {
    cerr << "error sending username" << endl;
    close(fd);
    return -1;
  }

  Message login_response(MessageType::LOGIN_REJECTED, "");
  if (!receive_secure_message(fd, login_response, session_key)) {
    cerr << "error receiving login response" << endl;
    close(fd);
    return -1;
  }
  if (login_response.type() != MessageType::LOGIN_ACCEPTED) {
    cerr << "Login failed: " << login_response.payload_as_string() << endl;
    close(fd);
    return -1;
  }

  cout << "Connected as " << username << endl;
  print_command_guide();

  pthread_t receiver_thread;
  ReceiveContext receive_context{fd, &session_key};
  if (pthread_create(&receiver_thread, nullptr, receive_messages,
                     &receive_context) != 0) {
    cerr << "error creating receiver thread" << endl;
    close(fd);
    return -1;
  }

  string selected_partner;
  string input;
  while (true) {
    print_prompt();
    if (!getline(cin, input)) {
      break;
    }

    const ClientCommand command =
        parse_client_command(input, selected_partner);

    if (command.type == ClientCommandType::QUIT) {
      break;
    }
    if (command.type == ClientCommandType::INVALID) {
      cerr << command.error << endl;
    } else if (command.type == ClientCommandType::SELECT_PARTNER) {
      selected_partner = command.recipient;
      cout << "Now chatting with " << selected_partner << endl;
    } else if (command.type == ClientCommandType::LIST_USERS) {
      if (!send_secure_message(fd, chat_protocol::who_request(), session_key)) {
        break;
      }
    } else if (command.type == ClientCommandType::SEND_MESSAGE) {
      selected_partner = command.recipient;
      if (!send_secure_message(
              fd,
              chat_protocol::direct_message(command.recipient, command.text),
              session_key)) {
        break;
      }
    }
  }

  shutdown(fd, SHUT_WR);
  pthread_join(receiver_thread, nullptr);
  close(fd);
  return 0;
}
