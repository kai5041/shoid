#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

#include <shoid/defs.hpp>

#include <shoid/uWebSockets/App.h>

namespace shoid {

bool is_port_in_use(int port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return true;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  bool in_use = bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0;
  close(sock);
  return in_use;
}

int start_daemon_command(Args &args) {
  int port = 7210;

  if (!args.empty()) {
    try {
      port = std::stoul(args[0]);
    } catch (...) {
      std::cerr << "Invalid port number\n";
      return 1;
    }
  }

  if (is_port_in_use(port)) {
    std::cerr << "Port " << port << " is already in use\n";
    return 1;
  }

  std::cout << "Starting daemon on port " << port << "\n";

  uWS::App()
      .get("/*",
           [](auto *res, auto *req) {
             res->end("<html><body><h1>Hello World</h1></body></html>");
           })
      .listen(port,
              [port](auto *token) {
                if (token) {
                  std::cout << "Listening on port " << port << "\n";
                } else {
                  std::cerr << "Failed to listen on port " << port << "\n";
                }
              })
      .run();

  return 0;
}

} // namespace shoid