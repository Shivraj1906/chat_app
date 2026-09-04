#pragma once

#include <string>

enum class ClientCommandType {
  SEND_MESSAGE,
  SELECT_PARTNER,
  LIST_USERS,
  QUIT,
  INVALID,
};

struct ClientCommand {
  ClientCommandType type;
  std::string recipient;
  std::string text;
  std::string error;
};

ClientCommand parse_client_command(const std::string &input,
                                   const std::string &selected_partner);
