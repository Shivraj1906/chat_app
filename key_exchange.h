#pragma once

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class Number {
private:
  std::vector<uint64_t> n; // 0xABCD --> n[0] = CD, n[1] = AB
  void trim() {
    while (n.size() > 1 && n.back() == 0)
      n.pop_back();
  }

public:
  Number() : n(1, 0) {}
  Number(uint64_t value) : n(1, value) {}
  explicit Number(const std::string &hex) {
    std::string s = hex;

    if (s.empty()) {
      n = {0};
      return;
    }
    if (s.size() > 512 || !std::all_of(s.begin(), s.end(), [](char character) {
          return std::isxdigit(static_cast<unsigned char>(character)) != 0;
        })) {
      throw std::invalid_argument("Invalid hexadecimal number");
    }

    for (int end = static_cast<int>(s.size()); end > 0; end -= 16) {
      int begin = std::max(0, end - 16);
      std::string chunk = s.substr(begin, end - begin);
      uint64_t part = std::stoull(chunk, nullptr, 16);
      n.push_back(part);
    }
    trim();
  }

  bool is_zero() const { return n.size() == 1 && n[0] == 0; }
  bool is_odd() const { return (n[0] & 1ULL) != 0; }
  std::size_t bit_length() const {
    if (is_zero())
      return 0;

    uint64_t ms = n.back();
    std::size_t bits = (n.size() - 1) * 64;
    while (ms != 0) {
      ++bits;
      ms >>= 1;
    }
    return bits;
  }

  bool get_bit(std::size_t index) const {
    std::size_t limb = index / 64;
    std::size_t offset = index % 64;

    if (limb >= n.size())
      return false;

    return ((n[limb] >> offset) & 1ULL) != 0;
  }

  std::string to_hex() const {
    std::ostringstream output;
    output << std::hex << n.back();
    for (std::size_t i = n.size() - 1; i-- > 0;)
      output << std::setw(16) << std::setfill('0') << n[i];
    return output.str();
  }

  friend bool operator==(const Number &a, const Number &b) {
    return a.n == b.n;
  }
  friend bool operator!=(const Number &a, const Number &b) { return !(a == b); }
  friend bool operator<(const Number &a, const Number &b) {
    if (a.n.size() != b.n.size())
      return a.n.size() < b.n.size();

    for (std::size_t i = a.n.size(); i-- > 0;) {
      if (a.n[i] != b.n[i])
        return a.n[i] < b.n[i];
    }

    return false;
  }
  friend bool operator>(const Number &a, const Number &b) { return b < a; }
  friend bool operator<=(const Number &a, const Number &b) { return !(b < a); }
  friend bool operator>=(const Number &a, const Number &b) { return !(a < b); }

  friend Number operator-(const Number &a, const Number &b) {
    assert(a >= b && "Negative results are not supported");
    Number result;

    result.n.assign(a.n.size(), 0);
    uint64_t borrow = 0;

    for (std::size_t i = 0; i < a.n.size(); ++i) {
      uint64_t av = a.n[i];
      uint64_t bv = (i < b.n.size()) ? b.n[i] : 0;
      uint64_t temp = av - bv;
      uint64_t borrow1 = (av < bv);
      uint64_t value = temp - borrow;
      uint64_t borrow2 = (temp < borrow);
      result.n[i] = value;
      borrow = borrow1 | borrow2;
    }
    result.trim();

    return result;
  }

  Number &operator>>=(unsigned amount) {
    while (amount--) {
      uint64_t carry = 0;
      for (std::size_t i = n.size(); i-- > 0;) {
        uint64_t new_carry = n[i] & 1ULL;
        n[i] >>= 1;
        n[i] |= carry << 63;
        carry = new_carry;
      }
      trim();
    }

    return *this;
  }

  friend Number operator>>(Number value, unsigned amount) {
    value >>= amount;
    return value;
  }

  Number &operator<<=(unsigned amount) {
    while (amount--) {
      uint64_t carry = 0;

      for (std::size_t i = 0; i < n.size(); ++i) {
        uint64_t new_carry = n[i] >> 63;
        n[i] <<= 1;
        n[i] |= carry;
        carry = new_carry;
      }

      if (carry != 0)
        n.push_back(carry);
    }

    return *this;
  }

  friend Number operator<<(Number value, unsigned amount) {
    value <<= amount;
    return value;
  }

  void add_one() {
    std::size_t i = 0;

    while (true) {
      if (i == n.size()) {
        n.push_back(1);
        return;
      }
      ++n[i];
      if (n[i] != 0)
        return;

      ++i;
    }
  }

  friend Number operator*(const Number &a, const Number &b) {
    if (a.is_zero() || b.is_zero())
      return Number(0);
    Number result;
    result.n.assign(a.n.size() + b.n.size(), 0);

    for (std::size_t i = 0; i < a.n.size(); ++i) {
      unsigned __int128 carry = 0;

      for (std::size_t j = 0; j < b.n.size(); ++j) {
        std::size_t k = i + j;

        unsigned __int128 product = static_cast<unsigned __int128>(a.n[i]) *
                                    static_cast<unsigned __int128>(b.n[j]);

        unsigned __int128 sum =
            static_cast<unsigned __int128>(result.n[k]) + product + carry;

        result.n[k] = static_cast<uint64_t>(sum);
        carry = sum >> 64;
      }

      std::size_t k = i + b.n.size();
      while (carry != 0) {
        if (k == result.n.size())
          result.n.push_back(0);

        unsigned __int128 sum =
            static_cast<unsigned __int128>(result.n[k]) + carry;

        result.n[k] = static_cast<uint64_t>(sum);
        carry = sum >> 64;
        ++k;
      }
    }

    result.trim();
    return result;
  }

  friend Number operator%(const Number &a, const Number &modulus) {
    if (modulus.is_zero())
      throw std::runtime_error("Modulo by zero");

    if (a < modulus)
      return a;

    Number remainder(0);
    for (std::size_t i = a.bit_length(); i-- > 0;) {
      remainder <<= 1;

      if (a.get_bit(i))
        remainder.add_one();

      if (remainder >= modulus)
        remainder = remainder - modulus;
    }
    return remainder;
  }

  void print_num() const { std::cout << to_hex() << '\n'; }
};

inline Number mod_exp(Number base, const Number &exponent,
                      const Number &modulus) {
  if (modulus.is_zero())
    throw std::runtime_error("Modular exponentiation with zero modulus");

  Number result = Number(1) % modulus;
  base = base % modulus;
  for (std::size_t i = 0; i < exponent.bit_length(); ++i) {
    if (exponent.get_bit(i))
      result = (result * base) % modulus;
    base = (base * base) % modulus;
  }
  return result;
}

// RFC 3526, section 3: 2048-bit MODP group (group identifier 14).
static const unsigned RFC3526_MODP_GROUP14_ID = 14;
static const unsigned RFC3526_MODP_GROUP14_BITS = 2048;

inline const Number &rfc3526_modp_group14_prime() {
  static const Number modulus("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                              "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                              "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                              "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                              "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                              "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                              "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                              "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                              "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                              "15728E5A8AACAA68FFFFFFFFFFFFFFFF");
  return modulus;
}

inline const Number &rfc3526_modp_group14_generator() {
  static const Number generator(2);
  return generator;
}

struct DhKeyPair {
  Number private_key;
  Number public_key;
};

inline Number dh_random_private_key() {
  std::random_device source;
  std::ostringstream hex;
  hex << std::hex << std::setfill('0');
  for (int i = 0; i < 2; ++i) {
    std::uint32_t word = source();
    if (i == 0)
      word |= 0x80000000U;
    hex << std::setw(8) << word;
  }
  return Number(hex.str());
}

inline DhKeyPair dh_generate_key_pair() {
  DhKeyPair pair;
  pair.private_key = dh_random_private_key();
  pair.public_key = mod_exp(rfc3526_modp_group14_generator(), pair.private_key,
                            rfc3526_modp_group14_prime());
  return pair;
}

inline bool dh_valid_public_key(const Number &public_key) {
  return public_key >= Number(2) &&
         public_key <= rfc3526_modp_group14_prime() - Number(2);
}

inline Number dh_shared_secret(const Number &peer_public_key,
                               const Number &private_key) {
  if (!dh_valid_public_key(peer_public_key))
    throw std::invalid_argument("Invalid Diffie-Hellman public key");
  return mod_exp(peer_public_key, private_key, rfc3526_modp_group14_prime());
}

inline std::string dh_encode_public_key(const Number &public_key) {
  return std::to_string(RFC3526_MODP_GROUP14_ID) + "\n" + public_key.to_hex();
}

inline Number dh_decode_public_key(const std::string &payload) {
  const std::size_t separator = payload.find('\n');
  if (separator == std::string::npos ||
      payload.substr(0, separator) != std::to_string(RFC3526_MODP_GROUP14_ID)) {
    throw std::invalid_argument("Unsupported Diffie-Hellman group");
  }

  const Number public_key(payload.substr(separator + 1));
  if (!dh_valid_public_key(public_key))
    throw std::invalid_argument("Invalid Diffie-Hellman public key");
  return public_key;
}
