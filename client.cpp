#include <arpa/inet.h>
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
#include "socket_io.h"

using namespace std;

pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

void print_prompt() {
  pthread_mutex_lock(&output_mutex);
  cout << "> " << flush;
  pthread_mutex_unlock(&output_mutex);
}

void *receive_messages(void *argument) {
  const int fd = *static_cast<int *>(argument);
  Message message(MessageType::CHAT_MESSAGE, "");

  while (receive_message(fd, message)) {
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
  if (argc != 4) {
    cerr << "Usage: " << argv[0] << " <server-ip> <port> <username>" << endl;
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

  const DhKeyPair dh_keys = dh_generate_key_pair();
  if (!send_message(fd,
                    Message(MessageType::DH_PUBLIC_KEY,
                            dh_encode_public_key(dh_keys.public_key)))) {
    cerr << "error sending Diffie-Hellman public key" << endl;
    close(fd);
    return -1;
  }

  Message server_key_message(MessageType::DH_PUBLIC_KEY, "");
  if (!receive_message(fd, server_key_message) ||
      server_key_message.type() != MessageType::DH_PUBLIC_KEY) {
    cerr << "error receiving Diffie-Hellman public key" << endl;
    close(fd);
    return -1;
  }

  Number shared_secret;
  try {
    shared_secret = dh_shared_secret(
        dh_decode_public_key(server_key_message.payload_as_string()),
        dh_keys.private_key);
  } catch (const std::exception &error) {
    cerr << "Diffie-Hellman exchange failed: " << error.what() << endl;
    close(fd);
    return -1;
  }
  cout << "DH shared secret: " << shared_secret.to_hex() << endl;

  if (!send_message(fd, chat_protocol::login_request(username))) {
    cerr << "error sending username" << endl;
    close(fd);
    return -1;
  }

  Message login_response(MessageType::LOGIN_REJECTED, "");
  if (!receive_message(fd, login_response)) {
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
  if (pthread_create(&receiver_thread, nullptr, receive_messages, &fd) != 0) {
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
      if (!send_message(fd, chat_protocol::who_request())) {
        break;
      }
    } else if (command.type == ClientCommandType::SEND_MESSAGE) {
      selected_partner = command.recipient;
      if (!send_message(fd, chat_protocol::direct_message(
                                command.recipient, command.text))) {
        break;
      }
    }
  }

  shutdown(fd, SHUT_WR);
  pthread_join(receiver_thread, nullptr);
  close(fd);
  return 0;
}
