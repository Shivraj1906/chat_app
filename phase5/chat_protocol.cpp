#include "chat_protocol.h"

namespace chat_protocol {

Message login_request(const std::string &username) {
  return Message(MessageType::CLIENT_HELLO, username);
}

Message login_accepted() {
  return Message(MessageType::LOGIN_ACCEPTED, "login accepted");
}

Message login_rejected(const std::string &reason) {
  return Message(MessageType::LOGIN_REJECTED, reason);
}

Message direct_message(const std::string &recipient, const std::string &text) {
  return Message(MessageType::DIRECT_MESSAGE, recipient + "\n" + text);
}

bool parse_direct_message(const Message &message, DirectMessage &result) {
  if (message.type() != MessageType::DIRECT_MESSAGE) {
    return false;
  }

  const std::string payload = message.payload_as_string();
  const std::size_t separator = payload.find('\n');
  if (separator == std::string::npos || separator == 0) {
    return false;
  }

  result.recipient = payload.substr(0, separator);
  result.text = payload.substr(separator + 1);
  return true;
}

Message delivered_message(const std::string &sender, const std::string &text) {
  return Message(MessageType::CHAT_MESSAGE, sender + ": " + text);
}

Message who_request() { return Message(MessageType::WHO_REQUEST, ""); }

Message who_response(const std::string &usernames) {
  return Message(MessageType::WHO_RESPONSE, usernames);
}

Message server_error(const std::string &error) {
  return Message(MessageType::SERVER_ERROR, error);
}

} // namespace chat_protocol
