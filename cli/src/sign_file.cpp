#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <string>

#include <shoid/defs.hpp>
#include <shoid/ed25519.hpp>

namespace shoid {

int sign_file_command(Args &args) {
  if (args.size() != 4) {
    std::cerr << "Usage: sign <algorithm> <file> <private_key_file> "
                 "<signature_file>\n";
    return 1;
  }

  const std::string &algorithm = args[0];
  const std::string &input_file_path = args[1];
  const std::string &private_key_path = args[2];
  const std::string &signature_path = args[3];

  static const std::map<std::string,
                        std::function<int(Bytes &, Bytes &, Bytes &)>>
      algorithms = {{"ed25519", shoid::sign_file_ed25519}};

  auto it = algorithms.find(algorithm);
  if (it == algorithms.end()) {
    std::cerr << "Unsupported algorithm: " << algorithm << "\n";
    return 1;
  }

  // Read the input file
  Bytes file_data;
  {
    std::ifstream f(input_file_path, std::ios::binary | std::ios::ate);
    if (!f) {
      std::cerr << "Failed to open input file: " << input_file_path << "\n";
      return 1;
    }
    std::streamsize size = f.tellg();
    if (size < 0) {
      std::cerr << "Failed to determine size of input file: " << input_file_path
                << "\n";
      return 1;
    }
    f.seekg(0);
    file_data.resize(size);
    if (!f.read(reinterpret_cast<char *>(file_data.data()), size)) {
      std::cerr << "Failed to read input file: " << input_file_path << "\n";
      return 1;
    }
  }

  // Read the private key
  Bytes private_key;
  {
    std::ifstream f(private_key_path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
      std::cerr << "Failed to open private key file: " << private_key_path
                << "\n";
      return 1;
    }

    std::streamsize size = f.tellg();
    if (size < 0) {
      std::cerr << "Failed to determine size of private key file: "
                << private_key_path << "\n";
      return 1;
    }
    f.seekg(0);
    private_key.resize(size);
    if (!f.read(reinterpret_cast<char *>(private_key.data()), size)) {
      std::cerr << "Failed to read private key file: " << private_key_path
                << "\n";
      return 1;
    }
  }

  Bytes public_key; // optional, not used in signing
  Bytes signature;

  int ret = it->second(signature, file_data, private_key);
  if (ret != 0) {
    std::cerr << "Signing failed for algorithm: " << algorithm << "\n";
    return ret;
  }

  // Write the signature to file
  {
    std::ofstream f(signature_path, std::ios::binary);
    if (!f) {
      std::cerr << "Failed to write signature file: " << signature_path << "\n";
      return 1;
    }
    f.write(reinterpret_cast<const char *>(signature.data()), signature.size());
    if (!f.good()) {
      std::cerr << "Failed to write signature file: " << signature_path << "\n";
      return 1;
    }
  }

  return 0;
}

} // namespace shoid
