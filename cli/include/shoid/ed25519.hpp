#pragma once

#include <string>
#include <vector>

namespace shoid {

int ed25519_generate_keypair(std::vector<std::string> args);
int __ed25519_generate_keypair(const std::string &output_dir);

int ed25519_sign(std::vector<std::string> args);
int __ed25519_sign(const std::string &filename, const std::string &keyfile,
  const std::string &sigfile);

int ed25519_verify(std::vector<std::string> args);
int __ed25519_verify(const std::string &filename, const std::string &sigfile,
  const std::string &pubkeyfile);

} // namespace shoid
