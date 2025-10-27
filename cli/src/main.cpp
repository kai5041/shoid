#include <functional>
#include <iostream>
#include <map>
#include <string>

#include <shoid/shoid.hpp>

using namespace shoid;

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: shoid <command> <args>\n";
    return 1;
  }

  const std::string command = argv[1];
  Args args(argv + 2, argv + argc);

  std::map<std::string, std::function<int(Args &)>> commands = {
      {"generate", generate_keypair_command},
      {"sign", sign_file_command},
      {"verify", verify_signature_command},
  };

  auto it = commands.find(command);
  if (it != commands.end()) {
    return it->second(args);
  }

  std::cerr << "Unknown command: " << command << "\n";
  return 1;
}
