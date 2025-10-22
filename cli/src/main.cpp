#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <shoid/ed25519.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct Command {
  std::string syntax;
  std::function<int(std::vector<std::string>)> exec;
};

std::map<std::string, Command> commands = {
    {"ed25519-generate-keypair",
     {"<output_dir>", shoid::ed25519_generate_keypair}},
    {"ed25519-sign",
     {"<filename> <private_key.pem> <output.sig>", shoid::ed25519_sign}},
    {"ed25519-verify",
     {"<filename> <signature.sig> <public_key.pem>", shoid::ed25519_verify}},
};

int main(int argc, char **argv) {
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <command> [arguments]\n";
    return 1;
  }

  std::string cmd = argv[1];

  auto it = commands.find(cmd);
  if (it == commands.end()) {
    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
  }

  std::vector<std::string> args(argv + 2, argv + argc);
  int ret = it->second.exec(args);

  if (ret != 0) {
    std::cerr << "Command '" << cmd << "' failed (code " << ret << ")\n";
  }

  return ret;
}
