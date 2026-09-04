#pragma once

#include "message.h"

#include <mutex>
#include <string>
#include <unordered_map>

class ClientRegistry {
public:
  bool register_client(const std::string &username, int fd,
                       const Message &confirmation, std::string &error);
  void remove(const std::string &username, int fd);
  bool send_to(const std::string &username, const Message &message);
  std::string online_users() const;

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, int> clients_;
};
