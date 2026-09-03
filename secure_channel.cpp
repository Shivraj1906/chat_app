#include "secure_channel.h"

#include "key_exchange.h"
#include "socket_io.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <limits>
#include <memory>

namespace {

constexpr std::uint8_t ENVELOPE_VERSION = 1;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t TAG_SIZE = 16;
constexpr std::size_t ENVELOPE_OVERHEAD = 1 + NONCE_SIZE + TAG_SIZE;

using CipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using PkeyContext =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

bool encrypt(const std::vector<std::uint8_t> &plaintext,
             const SessionKey &key, std::vector<std::uint8_t> &envelope) {
  if (plaintext.size() >
      static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;

  envelope.assign(ENVELOPE_OVERHEAD + plaintext.size(), 0);
  envelope[0] = ENVELOPE_VERSION;
  std::uint8_t *nonce = envelope.data() + 1;
  std::uint8_t *tag = nonce + NONCE_SIZE;
  std::uint8_t *ciphertext = tag + TAG_SIZE;
  if (RAND_bytes(nonce, NONCE_SIZE) != 1)
    return false;

  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context ||
      EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE,
                          nullptr) != 1 ||
      EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce) !=
          1)
    return false;

  int written = 0;
  int final_written = 0;
  if (EVP_EncryptUpdate(context.get(), ciphertext, &written, plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1 ||
      EVP_EncryptFinal_ex(context.get(), ciphertext + written,
                          &final_written) != 1 ||
      EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) !=
          1)
    return false;

  envelope.resize(ENVELOPE_OVERHEAD + static_cast<std::size_t>(written) +
                  static_cast<std::size_t>(final_written));
  return true;
}

bool decrypt(const Message &encrypted, const SessionKey &key,
             std::vector<std::uint8_t> &plaintext) {
  if (encrypted.type() != MessageType::ENCRYPTED_MESSAGE ||
      encrypted.payload_size() <= ENVELOPE_OVERHEAD)
    return false;

  const std::uint8_t *payload = encrypted.payload_data();
  if (payload[0] != ENVELOPE_VERSION)
    return false;

  const std::uint8_t *nonce = payload + 1;
  const std::uint8_t *tag = nonce + NONCE_SIZE;
  const std::uint8_t *ciphertext = tag + TAG_SIZE;
  const std::size_t ciphertext_size =
      encrypted.payload_size() - ENVELOPE_OVERHEAD;
  if (ciphertext_size >
      static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;

  plaintext.assign(ciphertext_size, 0);
  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context ||
      EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE,
                          nullptr) != 1 ||
      EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce) !=
          1)
    return false;

  int written = 0;
  if (EVP_DecryptUpdate(context.get(), plaintext.data(), &written, ciphertext,
                        static_cast<int>(ciphertext_size)) != 1 ||
      EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                          const_cast<std::uint8_t *>(tag)) != 1)
    return false;

  int final_written = 0;
  if (EVP_DecryptFinal_ex(context.get(), plaintext.data() + written,
                          &final_written) != 1)
    return false;

  plaintext.resize(static_cast<std::size_t>(written + final_written));
  return true;
}

} // namespace

bool derive_session_key(const Number &shared_secret, SessionKey &key) {
  const std::vector<std::uint8_t> secret =
      shared_secret.to_bytes(RFC3526_MODP_GROUP14_BITS / 8);
  static const std::uint8_t salt[] = "chat-app HKDF-SHA256 salt v1";
  static const std::uint8_t info[] = "chat-app AES-256-GCM key v1";

  PkeyContext context(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr),
                      EVP_PKEY_CTX_free);
  std::size_t key_size = key.size();
  return context && EVP_PKEY_derive_init(context.get()) == 1 &&
         EVP_PKEY_CTX_set_hkdf_md(context.get(), EVP_sha256()) == 1 &&
         EVP_PKEY_CTX_set1_hkdf_salt(context.get(), salt,
                                     sizeof(salt) - 1) == 1 &&
         EVP_PKEY_CTX_set1_hkdf_key(context.get(), secret.data(),
                                    secret.size()) == 1 &&
         EVP_PKEY_CTX_add1_hkdf_info(context.get(), info,
                                     sizeof(info) - 1) == 1 &&
         EVP_PKEY_derive(context.get(), key.data(), &key_size) == 1 &&
         key_size == key.size();
}

bool send_secure_message(int fd, const Message &message,
                         const SessionKey &key) {
  if (message.type() == MessageType::ENCRYPTED_MESSAGE)
    return false;

  std::vector<std::uint8_t> plaintext(1 + message.payload_size());
  plaintext[0] = static_cast<std::uint8_t>(message.type());
  if (message.payload_size() != 0)
    std::copy(message.payload_data(),
              message.payload_data() + message.payload_size(),
              plaintext.begin() + 1);

  std::vector<std::uint8_t> envelope;
  return encrypt(plaintext, key, envelope) &&
         send_message(fd, Message(MessageType::ENCRYPTED_MESSAGE,
                                  envelope.data(), envelope.size()));
}

bool receive_secure_message(int fd, Message &message, const SessionKey &key,
                            std::size_t max_payload_size) {
  Message encrypted(MessageType::ENCRYPTED_MESSAGE, "");
  if (!receive_message(fd, encrypted, max_payload_size + ENVELOPE_OVERHEAD + 1))
    return false;

  std::vector<std::uint8_t> plaintext;
  if (!decrypt(encrypted, key, plaintext) || plaintext.empty() ||
      plaintext[0] >= static_cast<std::uint8_t>(MessageType::COUNT) ||
      plaintext[0] ==
          static_cast<std::uint8_t>(MessageType::ENCRYPTED_MESSAGE) ||
      plaintext.size() - 1 > max_payload_size)
    return false;

  message = Message(static_cast<MessageType>(plaintext[0]),
                    plaintext.data() + 1, plaintext.size() - 1);
  return true;
}
