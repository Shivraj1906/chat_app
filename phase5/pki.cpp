#include "pki.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <cstdio>
#include <fstream>
#include <limits>
#include <memory>

namespace {
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
using PublicKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Store = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using StoreContext =
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;
using CipherContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

Certificate parse_certificate(const std::vector<std::uint8_t> &pem) {
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio)
    return Certificate(nullptr, X509_free);
  Certificate certificate(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr),
                          X509_free);
  BIO_free(bio);
  return certificate;
}

PublicKey read_private_key(const std::string &path) {
  FILE *file = std::fopen(path.c_str(), "rb");
  if (!file)
    return PublicKey(nullptr, EVP_PKEY_free);
  PublicKey key(PEM_read_PrivateKey(file, nullptr, nullptr, nullptr),
                EVP_PKEY_free);
  std::fclose(file);
  return key;
}

} // namespace

bool read_binary_file(const std::string &path,
                      std::vector<std::uint8_t> &data) {
  std::ifstream file(path, std::ios::binary);
  if (!file)
    return false;
  data.assign(std::istreambuf_iterator<char>(file),
              std::istreambuf_iterator<char>());
  return !data.empty();
}

bool verify_server_certificate(const std::vector<std::uint8_t> &certificate_pem,
                               const std::string &ca_certificate_path,
                               const std::string &expected_server_identity) {
  Certificate certificate = parse_certificate(certificate_pem);
  if (!certificate)
    return false;

  Store store(X509_STORE_new(), X509_STORE_free);
  if (!store || X509_STORE_load_locations(
                    store.get(), ca_certificate_path.c_str(), nullptr) != 1)
    return false;

  StoreContext context(X509_STORE_CTX_new(), X509_STORE_CTX_free);
  if (!context ||
      X509_STORE_CTX_init(context.get(), store.get(), certificate.get(),
                          nullptr) != 1 ||
      X509_verify_cert(context.get()) != 1)
    return false;

  if (expected_server_identity.find_first_not_of("0123456789.") ==
      std::string::npos) {
    return X509_check_ip_asc(certificate.get(),
                             expected_server_identity.c_str(), 0) == 1;
  }
  return X509_check_host(certificate.get(), expected_server_identity.c_str(),
                         expected_server_identity.size(), 0, nullptr) == 1;
}

bool sign_handshake_value(const std::string &private_key_path,
                          const std::vector<std::uint8_t> &value,
                          std::vector<std::uint8_t> &signature) {
  PublicKey key = read_private_key(private_key_path);
  CipherContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!key || !context ||
      EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr,
                         key.get()) != 1 ||
      EVP_DigestSignUpdate(context.get(), value.data(), value.size()) != 1)
    return false;

  std::size_t size = 0;
  if (EVP_DigestSignFinal(context.get(), nullptr, &size) != 1)
    return false;
  signature.resize(size);
  if (EVP_DigestSignFinal(context.get(), signature.data(), &size) != 1)
    return false;
  signature.resize(size);
  return true;
}

bool verify_handshake_signature(
    const std::vector<std::uint8_t> &certificate_pem,
    const std::vector<std::uint8_t> &value,
    const std::vector<std::uint8_t> &signature) {
  Certificate certificate = parse_certificate(certificate_pem);
  PublicKey key(certificate ? X509_get_pubkey(certificate.get()) : nullptr,
                EVP_PKEY_free);
  CipherContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  return key && context &&
         EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr,
                              key.get()) == 1 &&
         EVP_DigestVerifyUpdate(context.get(), value.data(), value.size()) ==
             1 &&
         EVP_DigestVerifyFinal(context.get(), signature.data(),
                               signature.size()) == 1;
}

std::string hex_encode(const std::vector<std::uint8_t> &bytes) {
  static const char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (std::uint8_t byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 0x0f]);
  }
  return result;
}

bool hex_decode(const std::string &text, std::vector<std::uint8_t> &bytes) {
  if (text.size() % 2 != 0)
    return false;
  bytes.clear();
  bytes.reserve(text.size() / 2);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const auto nibble = [](char character) -> int {
      if (character >= '0' && character <= '9')
        return character - '0';
      if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
      if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
      return -1;
    };
    const int high = nibble(text[i]);
    const int low = nibble(text[i + 1]);
    if (high < 0 || low < 0)
      return false;
    bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return true;
}

std::string sha256_hex(const std::vector<std::uint8_t> &bytes) {
  unsigned char digest[EVP_MAX_MD_SIZE] = {};
  unsigned int digest_size = 0;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  if (!context || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(context, bytes.data(), bytes.size()) != 1 ||
      EVP_DigestFinal_ex(context, digest, &digest_size) != 1) {
    EVP_MD_CTX_free(context);
    return std::string();
  }
  EVP_MD_CTX_free(context);
  return hex_encode(std::vector<std::uint8_t>(digest, digest + digest_size));
}

bool random_bytes(std::size_t size, std::vector<std::uint8_t> &bytes) {
  if (size > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;
  bytes.resize(size);
  return size == 0 || RAND_bytes(bytes.data(), static_cast<int>(size)) == 1;
}
