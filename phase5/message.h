#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class MessageType : std::uint8_t {
  CLIENT_HELLO = 0,
  SERVER_RESPONSE = 1,
  CHAT_MESSAGE = 2,
  LOGIN_ACCEPTED = 3,
  LOGIN_REJECTED = 4,
  DIRECT_MESSAGE = 5,
  WHO_REQUEST = 6,
  WHO_RESPONSE = 7,
  SERVER_ERROR = 8,
  DH_PUBLIC_KEY = 9,
  ENCRYPTED_MESSAGE = 10,
  SERVER_CERTIFICATE = 11,
  CLIENT_KEY_EXCHANGE = 12,
  SERVER_KEY_EXCHANGE = 13,
  // Add new message types above COUNT. Header validation updates automatically.
  COUNT
};

// Wire format: one byte for the type, four bytes for the payload size in
// network byte order, followed by the payload.
class Message {
public:
  static constexpr std::size_t HEADER_SIZE = 5;
  using Header = std::array<std::uint8_t, HEADER_SIZE>;

  Message(MessageType type, const std::string &payload);
  Message(MessageType type, const void *payload, std::size_t size);

  MessageType type() const noexcept { return type_; }
  std::uint32_t payload_size() const noexcept;
  const std::uint8_t *payload_data() const noexcept;
  std::string payload_as_string() const;

  Header header() const noexcept;
  static bool decode_header(const Header &header, MessageType &type,
                            std::uint32_t &payload_size) noexcept;

private:
  MessageType type_;
  std::vector<std::uint8_t> payload_;
};
