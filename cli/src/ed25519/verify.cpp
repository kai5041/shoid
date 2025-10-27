#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <shoid/ed25519.hpp>

namespace shoid {

int verify_signature_ed25519(Bytes &data, Bytes &signature, Bytes &public_key) {
  if (public_key.size() != 32) {
    std::cerr << "Invalid Ed25519 public key size\n";
    return -1;
  }

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
  if (!pkey) {
    std::cerr << "Failed to load Ed25519 public key: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    std::cerr << "Failed to create digest context: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_PKEY_free(pkey);
    return -1;
  }

  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
    std::cerr << "DigestVerifyInit failed: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return -1;
  }

  int ret = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                             data.data(), data.size());

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  if (ret == 1) {
    return 0; // Signature valid
  } else if (ret == 0) {
    return 1; // Signature invalid
  } else {
    std::cerr << "Error during verification: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    return -1; // Verification error
  }
}

} // namespace shoid
