#pragma once

#include <shoid/defs.hpp>

namespace shoid {

int generate_keypair_ed25519(Bytes &public_key, Bytes &private_key);
int sign_file_ed25519(Bytes &signature, Bytes &data, Bytes &private_key);
int verify_signature_ed25519(Bytes &data, Bytes &signature, Bytes &public_key);

}
