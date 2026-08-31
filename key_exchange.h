#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

int mod_exp(int base, int exponent, int modulus) {
  int result = 1;
  base = base % modulus; // 3
  while (exponent > 0) {
    if (exponent % 2 != 0)
      result = (result * base) % modulus; // 3

    exponent = exponent >> 1;
    base = (base * base) % modulus;
  }
  return result;
}

// Represents an N bit number
class Number {
  int bits;
  int arr_size;
  std::vector<uint8_t> n; // 0xABCD --> n[0] = AB, n[1] = CD
  static std::unordered_map<char, uint8_t> hex_lookup;

public:
  Number(std::string hex, int bits)
      : bits(bits), arr_size(bits / 8), n(arr_size, 0) {
    std::cout << "ARRAY SIZE: " << arr_size << std::endl;
    int idx = 0;
    for (auto it = hex.rbegin(); it != hex.rend(); it++) {
      uint8_t nibble = idx % 2 == 0 ? hex_lookup[*it] : (hex_lookup[*it] << 4);
      n[arr_size - (idx / 2) - 1] |= nibble;
      idx++;
    }
  }

  void print_num() {
    for (auto it = n.begin(); it != n.end(); it++)
      std::cout << std::hex << ((int) (*it)) << " ";
    std::cout << std::dec << std::endl;
  }
};

std::unordered_map<char, uint8_t> Number::hex_lookup = {
    {'0', 0},  {'1', 1},  {'2', 2},  {'3', 3}, {'4', 4},  {'5', 5},
    {'6', 6},  {'7', 7},  {'8', 8},  {'9', 9}, {'A', 10}, {'B', 11},
    {'C', 12}, {'D', 13}, {'E', 14}, {'F', 15}};
