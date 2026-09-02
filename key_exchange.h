#pragma once

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <iostream>
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

  void print_num() const {
    std::cout << std::hex;
    std::cout << n.back();
    for (std::size_t i = n.size() - 1; i-- > 0;)
      std::cout << std::setw(16) << std::setfill('0') << n[i];

    std::cout << std::setfill(' ') << std::dec << '\n';
  }
};
