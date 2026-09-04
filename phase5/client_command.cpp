#include "client_command.h"

namespace {

ClientCommand command(ClientCommandType type, const std::string &recipient = "",
                      const std::string &text = "",
                      const std::string &error = "") {
  return {type, recipient, text, error};
}

} // namespace

ClientCommand parse_client_command(const std::string &input,
                                   const std::string &selected_partner) {
  if (input == "/quit") {
    return command(ClientCommandType::QUIT);
  }
  if (input == "/who") {
    return command(ClientCommandType::LIST_USERS);
  }
  if (input.compare(0, 5, "/e2e ") == 0) {
    const std::string username = input.substr(5);
    if (username.empty())
      return command(ClientCommandType::INVALID, "", "",
                     "Usage: /e2e <username>");
    return command(ClientCommandType::START_E2E, username);
  }
  if (input.compare(0, 6, "/chat ") == 0) {
    const std::string username = input.substr(6);
    if (username.empty()) {
      return command(ClientCommandType::INVALID, "", "",
                     "Usage: /chat <username>");
    }
    return command(ClientCommandType::SELECT_PARTNER, username);
  }
  if (!input.empty() && input[0] == '@') {
    const std::size_t separator = input.find(' ');
    if (separator == std::string::npos || separator == 1 ||
        separator + 1 == input.size()) {
      return command(ClientCommandType::INVALID, "", "",
                     "Usage: @<username> <message>");
    }
    return command(ClientCommandType::SEND_MESSAGE,
                   input.substr(1, separator - 1),
                   input.substr(separator + 1));
  }
  if (!input.empty() && input[0] == '/') {
    return command(ClientCommandType::INVALID, "", "", "Unknown command");
  }
  if (selected_partner.empty()) {
    return command(ClientCommandType::INVALID, "", "",
                   "Select a chat partner with /chat <username> or "
                   "@<username>");
  }
  return command(ClientCommandType::SEND_MESSAGE, selected_partner, input);
}
