#pragma once

#include <shoid/defs.hpp>

namespace shoid {

int generate_keypair_command(Args &args);
int sign_file_command(Args &args);
int verify_signature_command(Args &args);

} // namespace shoid