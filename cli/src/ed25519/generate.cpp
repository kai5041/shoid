#include <shoid/ed25519.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <cerrno>
#include <iostream>

namespace shoid {

int generate_keypair_ed25519(Bytes &public_key, Bytes &private_key) {
  EVP_PKEY_CTX *ctx = nullptr;
  EVP_PKEY *pkey = nullptr;

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!ctx) {
    std::cerr << "Failed to create EVP_PKEY_CTX: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    return -1;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    std::cerr << "Failed to initialize Ed25519 key generation: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    std::cerr << "Failed to generate Ed25519 keypair: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);

  std::size_t pub_len = 32;
  std::size_t priv_len = 32;

  public_key.resize(pub_len);
  private_key.resize(priv_len);

  if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &pub_len) <= 0) {
    std::cerr << "Failed to extract Ed25519 public key: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_PKEY_free(pkey);
    return -1;
  }

  if (EVP_PKEY_get_raw_private_key(pkey, private_key.data(), &priv_len) <= 0) {
    std::cerr << "Failed to extract Ed25519 private key: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_free(pkey);
  return 0;
}

} // namespace shoid
