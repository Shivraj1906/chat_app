#pragma once

#include "message.h"

#include <string>

namespace chat_protocol {

struct DirectMessage {
  std::string recipient;
  std::string text;
};

Message login_request(const std::string &username);
Message login_accepted();
Message login_rejected(const std::string &reason);

Message direct_message(const std::string &recipient, const std::string &text);
bool parse_direct_message(const Message &message, DirectMessage &result);
Message delivered_message(const std::string &sender, const std::string &text);

Message who_request();
Message who_response(const std::string &usernames);
Message server_error(const std::string &error);

} // namespace chat_protocol
