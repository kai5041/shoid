#pragma once

#include <shoid/defs.hpp>

#include <iostream>

namespace shoid {

int generate_keypair_command(Args &args);
int sign_file_command(Args &args);
int verify_signature_command(Args &args);
int start_daemon_command(Args &args);

inline int version_command(Args &) {
  std::cout << "ShoID v0.0.0\nRepository: https://github.com/kai5041/shoid\n";
  return 0;
}

} // namespace shoid