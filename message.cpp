#include "message.h"

#include <limits>
#include <stdexcept>

namespace {

bool is_known_message_type(std::uint8_t value) {
  return value < static_cast<std::uint8_t>(MessageType::COUNT);
}

} // namespace

Message::Message(MessageType type, const std::string &payload)
    : Message(type, payload.data(), payload.size()) {}

Message::Message(MessageType type, const void *payload, std::size_t size)
    : type_(type) {
  if (size > std::numeric_limits<std::uint32_t>::max()) {
    throw std::length_error("message payload is too large");
  }
  if (size != 0 && payload == nullptr) {
    throw std::invalid_argument("a non-empty message needs a payload");
  }

  const auto *bytes = static_cast<const std::uint8_t *>(payload);
  if (size != 0) {
    payload_.assign(bytes, bytes + size);
  }
}

std::uint32_t Message::payload_size() const noexcept {
  return static_cast<std::uint32_t>(payload_.size());
}

const std::uint8_t *Message::payload_data() const noexcept {
  return payload_.empty() ? nullptr : payload_.data();
}

std::string Message::payload_as_string() const {
  return std::string(payload_.begin(), payload_.end());
}

Message::Header Message::header() const noexcept {
  const std::uint32_t size = payload_size();
  return {{static_cast<std::uint8_t>(type_),
           static_cast<std::uint8_t>((size >> 24) & 0xff),
           static_cast<std::uint8_t>((size >> 16) & 0xff),
           static_cast<std::uint8_t>((size >> 8) & 0xff),
           static_cast<std::uint8_t>(size & 0xff)}};
}

bool Message::decode_header(const Header &header, MessageType &type,
                            std::uint32_t &payload_size) noexcept {
  if (!is_known_message_type(header[0])) {
    return false;
  }

  type = static_cast<MessageType>(header[0]);
  payload_size = (static_cast<std::uint32_t>(header[1]) << 24) |
                 (static_cast<std::uint32_t>(header[2]) << 16) |
                 (static_cast<std::uint32_t>(header[3]) << 8) |
                 static_cast<std::uint32_t>(header[4]);
  return true;
}
