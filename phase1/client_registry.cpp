#include "client_registry.h"

#include "socket_io.h"

#include <algorithm>
#include <sstream>
#include <vector>

bool ClientRegistry::register_client(const std::string &username, int fd,
                                     const Message &confirmation,
                                     std::string &error) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (username.empty()) {
    error = "username cannot be empty";
    return false;
  }
  if (clients_.find(username) != clients_.end()) {
    error = "username is already taken";
    return false;
  }

  clients_[username] = fd;
  if (!send_message(fd, confirmation)) {
    clients_.erase(username);
    return false;
  }
  return true;
}

void ClientRegistry::remove(const std::string &username, int fd) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto client = clients_.find(username);
  if (client != clients_.end() && client->second == fd) {
    clients_.erase(client);
  }
}

bool ClientRegistry::send_to(const std::string &username,
                             const Message &message) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto client = clients_.find(username);
  return client != clients_.end() && send_message(client->second, message);
}

std::string ClientRegistry::online_users() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> usernames;
  for (const auto &client : clients_) {
    usernames.push_back(client.first);
  }
  std::sort(usernames.begin(), usernames.end());

  std::ostringstream result;
  for (std::size_t i = 0; i < usernames.size(); ++i) {
    if (i != 0) {
      result << ", ";
    }
    result << usernames[i];
  }
  return result.str();
}
