#pragma once

#include <cstdint>
#include <string>
#include <vector>

// PEM certificate/key helpers used by the Phase 3 handshake.
bool read_binary_file(const std::string &path, std::vector<std::uint8_t> &data);
bool verify_server_certificate(const std::vector<std::uint8_t> &certificate_pem,
                               const std::string &ca_certificate_path,
                               const std::string &expected_server_identity);
bool sign_handshake_value(const std::string &private_key_path,
                          const std::vector<std::uint8_t> &value,
                          std::vector<std::uint8_t> &signature);
bool verify_handshake_signature(
    const std::vector<std::uint8_t> &certificate_pem,
    const std::vector<std::uint8_t> &value,
    const std::vector<std::uint8_t> &signature);

std::string hex_encode(const std::vector<std::uint8_t> &bytes);
bool hex_decode(const std::string &text, std::vector<std::uint8_t> &bytes);
std::string sha256_hex(const std::vector<std::uint8_t> &bytes);
bool random_bytes(std::size_t size, std::vector<std::uint8_t> &bytes);
