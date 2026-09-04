#include "socket_io.h"

#include <cerrno>
#include <cstdint>
#include <sys/socket.h>
#include <vector>

bool send_fixed(int fd, const void *buffer, std::size_t n) {
  const auto *bytes = static_cast<const std::uint8_t *>(buffer);
  std::size_t bytes_sent = 0;

  while (bytes_sent < n) {
    const ssize_t sent =
        send(fd, bytes + bytes_sent, n - bytes_sent, MSG_NOSIGNAL);
    if (sent < 0 && errno == EINTR) {
      continue;
    }
    if (sent <= 0) {
      return false;
    }
    bytes_sent += static_cast<std::size_t>(sent);
  }
  return true;
}

bool receive_fixed(int fd, void *buffer, std::size_t n) {
  auto *bytes = static_cast<std::uint8_t *>(buffer);
  std::size_t bytes_received = 0;

  while (bytes_received < n) {
    const ssize_t received =
        recv(fd, bytes + bytes_received, n - bytes_received, 0);
    if (received < 0 && errno == EINTR) {
      continue;
    }
    if (received <= 0) {
      return false;
    }
    bytes_received += static_cast<std::size_t>(received);
  }
  return true;
}

bool send_message(int fd, const Message &message) {
  const Message::Header header = message.header();
  if (!send_fixed(fd, header.data(), header.size())) {
    return false;
  }

  return message.payload_size() == 0 ||
         send_fixed(fd, message.payload_data(), message.payload_size());
}

bool receive_message(int fd, Message &message, std::size_t max_payload_size) {
  Message::Header header{};
  if (!receive_fixed(fd, header.data(), header.size())) {
    return false;
  }

  MessageType type = MessageType::CLIENT_HELLO;
  std::uint32_t payload_size = 0;
  if (!Message::decode_header(header, type, payload_size) ||
      payload_size > max_payload_size) {
    return false;
  }

  std::vector<std::uint8_t> payload(payload_size);
  if (payload_size != 0 &&
      !receive_fixed(fd, payload.data(), payload.size())) {
    return false;
  }

  message = Message(type, payload.data(), payload.size());
  return true;
}
