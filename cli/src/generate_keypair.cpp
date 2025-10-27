#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <string>

#include <shoid/ed25519.hpp>

namespace shoid {

// <algorithm> <output_prefix>
int generate_keypair_command(Args &args) {
  if (args.size() != 2) {
    std::cerr << "Usage: generate <algorithm> <output_prefix>\n";
    return 1;
  }

  const std::string &algorithm = args[0];
  const std::string &output_prefix = args[1];

  static const std::map<std::string, std::function<int(Bytes &, Bytes &)>>
      algorithms = {{"ed25519", shoid::generate_keypair_ed25519}};

  auto it = algorithms.find(algorithm);
  if (it == algorithms.end()) {
    std::cerr << "Unsupported algorithm: " << algorithm << "\n";
    return 1;
  }

  Bytes public_key;
  Bytes private_key;

  int ret = it->second(public_key, private_key);
  if (ret != 0) {
    std::cerr << "Key generation failed for " << algorithm << "\n";
    return ret;
  }

  auto write_file = [](const std::string &path, const Bytes &data) -> bool {
    std::ofstream f(path, std::ios::binary);
    if (!f)
      return false;
    f.write(reinterpret_cast<const char *>(data.data()), data.size());
    return f.good();
  };

  const std::string pub_path = output_prefix + "_public.bin";
  const std::string priv_path = output_prefix + "_private.bin";

  if (!write_file(pub_path, public_key)) {
    std::cerr << "Failed to write " << pub_path << "\n";
    return 1;
  }

  if (!write_file(priv_path, private_key)) {
    std::cerr << "Failed to write " << priv_path << "\n";
    return 1;
  }

  return 0;
}

} // namespace shoid
