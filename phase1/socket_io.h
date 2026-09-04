#pragma once

#include "message.h"

#include <cstddef>

// These functions only return true after exactly n bytes have been moved.
bool send_fixed(int fd, const void *buffer, std::size_t n);
bool receive_fixed(int fd, void *buffer, std::size_t n);

bool send_message(int fd, const Message &message);

// Reject unexpectedly large payloads before allocating memory for them.
bool receive_message(int fd, Message &message,
                     std::size_t max_payload_size = 1024 * 1024);
