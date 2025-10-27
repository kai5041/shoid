#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <string>

#include <shoid/defs.hpp>
#include <shoid/ed25519.hpp>

namespace shoid {

// <algorithm> <file> <signature_file> <public_key_file>
int verify_signature_command(Args &args) {
  if (args.size() != 4) {
    std::cerr << "Usage: sign <algorithm> <file> <signature_file> "
                 "<public_key_file>\n";
    return 1;
  }

  const std::string &algorithm = args[0];
  const std::string &input_file_path = args[1];
  const std::string &signature_path = args[2];
  const std::string &public_key_path = args[3];

  static const std::map<std::string,
                        std::function<int(Bytes &, Bytes &, Bytes &)>>
      algorithms = {{"ed25519", shoid::verify_signature_ed25519}};

  auto it = algorithms.find(algorithm);
  if (it == algorithms.end()) {
    std::cerr << "Unsupported algorithm: " << algorithm << "\n";
    return 1;
  }

  Bytes data, signature, public_key;

  // Load file data
  {
    std::ifstream file(input_file_path, std::ios::binary);
    if (!file) {
      std::cerr << "Cannot open file: " << input_file_path << "\n";
      return 1;
    }
    data.assign((std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>());
  }

  // Load signature
  {
    std::ifstream sigfile(signature_path, std::ios::binary);
    if (!sigfile) {
      std::cerr << "Cannot open signature file: " << signature_path << "\n";
      return 1;
    }
    signature.assign((std::istreambuf_iterator<char>(sigfile)),
                     std::istreambuf_iterator<char>());
  }

  // Load public key
  {
    std::ifstream pkfile(public_key_path, std::ios::binary);
    if (!pkfile) {
      std::cerr << "Cannot open public key file: " << public_key_path << "\n";
      return 1;
    }
    public_key.assign((std::istreambuf_iterator<char>(pkfile)),
                      std::istreambuf_iterator<char>());
  }

  int ret = it->second(data, signature, public_key);
  if (ret == 0) {
    std::cout << "Signature is VALID.\n";
  } else if (ret == 1) {
    std::cout << "Signature is INVALID.\n";
  } else {
    std::cerr << "Error during verification.\n";
  }

  return ret;
}

} // namespace shoid
