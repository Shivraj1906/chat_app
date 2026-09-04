#pragma once

#include "message.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

class Number;

using SessionKey = std::array<std::uint8_t, 32>;

// Serialize the group-14 shared secret to exactly 256 big-endian bytes and
// derive the AES-256 key with HKDF-SHA256.
bool derive_session_key(const Number &shared_secret, SessionKey &key);

// Post-handshake wire format is an ENCRYPTED_MESSAGE containing:
// version (1 byte) || nonce (12 bytes) || GCM tag (16 bytes) || ciphertext.
bool send_secure_message(int fd, const Message &message, const SessionKey &key);
bool receive_secure_message(int fd, Message &message, const SessionKey &key,
                            std::size_t max_payload_size = 1024 * 1024);

// AES-GCM helpers for the client-to-client inner layer. The returned envelope
// is version || nonce || tag || ciphertext, ready for an application wrapper.
bool encrypt_payload(const std::vector<std::uint8_t> &plaintext,
                     const SessionKey &key,
                     std::vector<std::uint8_t> &envelope);
bool decrypt_payload(const std::vector<std::uint8_t> &envelope,
                     const SessionKey &key,
                     std::vector<std::uint8_t> &plaintext);
