#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <condition_variable>
#include <iostream>
#include <map>
#include <mutex>
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

struct E2eState {
  std::mutex mutex;
  std::mutex send_mutex;
  std::map<std::string, SessionKey> sessions;
  struct PendingExchange {
    DhKeyPair keys;
    std::string token;
  };
  struct PendingSession {
    SessionKey key;
    std::string token;
  };
  std::map<std::string, PendingExchange> pending;
  std::map<std::string, PendingSession> incoming;
  bool stop_timer = false;
  std::condition_variable timer_condition;
};

struct ReceiveContext {
  int fd;
  const SessionKey *key;
  E2eState *e2e;
  std::string username;
};

bool split_delivered_message(const Message &message, std::string &sender,
                             std::string &text) {
  if (message.type() != MessageType::CHAT_MESSAGE)
    return false;
  const std::string payload = message.payload_as_string();
  const std::size_t separator = payload.find(": ");
  if (separator == std::string::npos || separator == 0)
    return false;
  sender = payload.substr(0, separator);
  text = payload.substr(separator + 2);
  return true;
}

bool send_to_server(int fd, const Message &message, const SessionKey &key,
                    E2eState &e2e) {
  std::lock_guard<std::mutex> lock(e2e.send_mutex);
  return send_secure_message(fd, message, key);
}

void print_e2e_fingerprint(const std::string &peer,
                           const SessionKey &session) {
  const std::vector<std::uint8_t> key_bytes(session.begin(), session.end());
  const std::string fingerprint = sha256_hex(key_bytes);
  pthread_mutex_lock(&output_mutex);
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  std::cout << "E2E session with " << peer << " established; timestamp=" << now
            << "; key fingerprint: " << fingerprint << std::endl;
  std::cout << "> " << std::flush;
  pthread_mutex_unlock(&output_mutex);
}

bool start_e2e_exchange(int fd, const SessionKey &server_key, E2eState &e2e,
                        const std::string &peer) {
  const DhKeyPair keys = dh_generate_key_pair();
  std::vector<std::uint8_t> token_bytes;
  if (!random_bytes(16, token_bytes))
    return false;
  const std::string token = hex_encode(token_bytes);
  {
    std::lock_guard<std::mutex> lock(e2e.mutex);
    e2e.pending[peer] = E2eState::PendingExchange{keys, token};
  }
  const std::string payload =
      chat_protocol::E2E_INIT_TAG + token + "\n" +
      dh_encode_public_key(keys.public_key);
  if (send_to_server(fd, chat_protocol::direct_message(peer, payload),
                     server_key, e2e))
    return true;
  std::lock_guard<std::mutex> lock(e2e.mutex);
  e2e.pending.erase(peer);
  return false;
}

bool handle_e2e_message(const Message &message, const SessionKey &server_key,
                        ReceiveContext &context) {
  std::string sender;
  std::string text;
  if (!split_delivered_message(message, sender, text))
    return false;

  const std::string init_tag = chat_protocol::E2E_INIT_TAG;
  const std::string ack_tag = chat_protocol::E2E_ACK_TAG;
  const std::string message_tag = chat_protocol::E2E_MESSAGE_TAG;
  if (text.compare(0, init_tag.size(), init_tag) == 0) {
    try {
      const std::string init = text.substr(init_tag.size());
      const std::size_t separator = init.find('\n');
      if (separator != 32 ||
          context.username < sender) {
        std::lock_guard<std::mutex> lock(context.e2e->mutex);
        if (context.username < sender &&
            context.e2e->sessions.find(sender) !=
                context.e2e->sessions.end())
          return true;
        if (separator != 32)
          return false;
      }
      const std::string token = init.substr(0, separator);
      const DhKeyPair keys = dh_generate_key_pair();
      const Number peer_public =
          dh_decode_public_key(init.substr(separator + 1));
      const Number shared = dh_shared_secret(peer_public, keys.private_key);
      SessionKey session{};
      if (!derive_session_key(shared, session))
        return false;
      {
        std::lock_guard<std::mutex> lock(context.e2e->mutex);
        context.e2e->incoming[sender] =
            E2eState::PendingSession{session, token};
      }
      const bool sent = send_to_server(
          context.fd,
          chat_protocol::direct_message(
              sender, ack_tag + token + "\n" +
                          dh_encode_public_key(keys.public_key)),
          server_key, *context.e2e);
      if (sent)
        return true;
      std::lock_guard<std::mutex> lock(context.e2e->mutex);
      context.e2e->incoming.erase(sender);
      return false;
    } catch (const std::exception &) {
      return false;
    }
  }

  if (text.compare(0, ack_tag.size(), ack_tag) == 0) {
    const std::string ack = text.substr(ack_tag.size());
    const std::size_t separator = ack.find('\n');
    if (separator != 32)
      return false;
    const std::string token = ack.substr(0, separator);
    const std::string data = ack.substr(separator + 1);

    // The initiator confirms receipt of the responder's public key with the
    // same ACK tag. This lets the responder switch keys before new messages
    // arrive, without a simultaneous-rotation race.
    if (data == "CONFIRM") {
      SessionKey session{};
      {
        std::lock_guard<std::mutex> lock(context.e2e->mutex);
        const auto incoming = context.e2e->incoming.find(sender);
        if (incoming == context.e2e->incoming.end() ||
            incoming->second.token != token)
          return false;
        session = incoming->second.key;
        context.e2e->incoming.erase(incoming);
        context.e2e->sessions[sender] = session;
      }
      print_e2e_fingerprint(sender, session);
      return true;
    }

    E2eState::PendingExchange pending_exchange;
    {
      std::lock_guard<std::mutex> lock(context.e2e->mutex);
      const auto pending = context.e2e->pending.find(sender);
      if (pending == context.e2e->pending.end() ||
          pending->second.token != token)
        return false;
      pending_exchange = pending->second;
    }
    try {
      const Number peer_public =
          dh_decode_public_key(data);
      const Number shared =
          dh_shared_secret(peer_public, pending_exchange.keys.private_key);
      SessionKey session{};
      if (!derive_session_key(shared, session))
        return false;
      if (!send_to_server(
              context.fd,
              chat_protocol::direct_message(
                  sender, ack_tag + token + "\nCONFIRM"),
              server_key, *context.e2e))
        return false;
      {
        std::lock_guard<std::mutex> lock(context.e2e->mutex);
        context.e2e->pending.erase(sender);
        context.e2e->sessions[sender] = session;
      }
      print_e2e_fingerprint(sender, session);
      return true;
    } catch (const std::exception &) {
      return false;
    }
  }

  if (text.compare(0, message_tag.size(), message_tag) == 0) {
    SessionKey session{};
    {
      std::lock_guard<std::mutex> lock(context.e2e->mutex);
      const auto found = context.e2e->sessions.find(sender);
      if (found == context.e2e->sessions.end())
        return false;
      session = found->second;
    }
    std::vector<std::uint8_t> envelope;
    std::vector<std::uint8_t> plaintext;
    if (!hex_decode(text.substr(message_tag.size()), envelope) ||
        !decrypt_payload(envelope, session, plaintext))
      return false;
    pthread_mutex_lock(&output_mutex);
    std::cout << '\r' << sender << ": "
              << std::string(plaintext.begin(), plaintext.end()) << std::endl;
    std::cout << "> " << std::flush;
    pthread_mutex_unlock(&output_mutex);
    return true;
  }
  return false;
}

struct RotationContext {
  int fd;
  const SessionKey *server_key;
  E2eState *e2e;
  std::string username;
};

void *rotation_timer(void *argument) {
  RotationContext &context = *static_cast<RotationContext *>(argument);
  unsigned interval = 60;
  if (const char *configured = std::getenv("CHAT_E2E_ROTATION_SECONDS")) {
    const long value = std::strtol(configured, nullptr, 10);
    if (value > 0)
      interval = static_cast<unsigned>(value);
  }

  while (true) {
    std::vector<std::string> peers;
    {
      std::unique_lock<std::mutex> lock(context.e2e->mutex);
      if (context.e2e->timer_condition.wait_for(
              lock, std::chrono::seconds(interval),
              [&context] { return context.e2e->stop_timer; }))
        return nullptr;
      // A deterministic initiator avoids simultaneous rotations: only the
      // lexicographically smaller username starts automatic renegotiation.
      for (const auto &session : context.e2e->sessions) {
        if (context.username < session.first)
          peers.push_back(session.first);
      }
    }
    for (const std::string &peer : peers)
      start_e2e_exchange(context.fd, *context.server_key, *context.e2e, peer);
  }
}

void print_prompt() {
  pthread_mutex_lock(&output_mutex);
  cout << "> " << flush;
  pthread_mutex_unlock(&output_mutex);
}

void *receive_messages(void *argument) {
  ReceiveContext &context = *static_cast<ReceiveContext *>(argument);
  const int fd = context.fd;
  Message message(MessageType::CHAT_MESSAGE, "");

  while (receive_secure_message(fd, message, *context.key)) {
    if (message.type() == MessageType::CHAT_MESSAGE &&
        handle_e2e_message(message, *context.key, context))
      continue;
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
       << "  /e2e <username>        Establish end-to-end encryption\n"
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

  E2eState e2e;
  pthread_t receiver_thread;
  ReceiveContext receive_context{fd, &session_key, &e2e, username};
  if (pthread_create(&receiver_thread, nullptr, receive_messages,
                     &receive_context) != 0) {
    cerr << "error creating receiver thread" << endl;
    close(fd);
    return -1;
  }
  pthread_t rotation_thread;
  RotationContext rotation_context{fd, &session_key, &e2e, username};
  if (pthread_create(&rotation_thread, nullptr, rotation_timer,
                     &rotation_context) != 0) {
    cerr << "error creating key rotation thread" << endl;
    shutdown(fd, SHUT_RDWR);
    pthread_join(receiver_thread, nullptr);
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
      if (!send_to_server(fd, chat_protocol::who_request(), session_key, e2e)) {
        break;
      }
    } else if (command.type == ClientCommandType::START_E2E) {
      selected_partner = command.recipient;
      if (!start_e2e_exchange(fd, session_key, e2e, command.recipient)) {
        break;
      }
      cout << "Started end-to-end key exchange with " << command.recipient
           << endl;
    } else if (command.type == ClientCommandType::SEND_MESSAGE) {
      selected_partner = command.recipient;
      SessionKey e2e_key{};
      bool use_e2e = false;
      {
        std::lock_guard<std::mutex> lock(e2e.mutex);
        const auto found = e2e.sessions.find(command.recipient);
        if (found != e2e.sessions.end()) {
          e2e_key = found->second;
          use_e2e = true;
        }
      }
      string text = command.text;
      if (use_e2e) {
        const vector<uint8_t> plaintext(text.begin(), text.end());
        vector<uint8_t> envelope;
        if (!encrypt_payload(plaintext, e2e_key, envelope))
          break;
        text = chat_protocol::E2E_MESSAGE_TAG + hex_encode(envelope);
      }
      if (!send_to_server(fd, chat_protocol::direct_message(command.recipient,
                                                              text),
                          session_key, e2e)) {
        break;
      }
    }
  }

  {
    std::lock_guard<std::mutex> lock(e2e.mutex);
    e2e.stop_timer = true;
  }
  e2e.timer_condition.notify_one();
  shutdown(fd, SHUT_WR);
  pthread_join(receiver_thread, nullptr);
  pthread_join(rotation_thread, nullptr);
  close(fd);
  return 0;
}
