#include <openssl/err.h>
#include <openssl/evp.h>

#include <iostream>

#include <shoid/ed25519.hpp>

namespace shoid {
int sign_file_ed25519(Bytes &signature, Bytes &data, Bytes &private_key) {
  if (private_key.size() != 32) {
    std::cerr << "Invalid private key size for Ed25519\n";
    return -1;
  }

  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
  if (!pkey) {
    std::cerr << "Failed to load Ed25519 private key: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    return -1;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    std::cerr << "Failed to create MD context: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_PKEY_free(pkey);
    return -1;
  }

  if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
    std::cerr << "Failed to initialize signing: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return -1;
  }

  size_t sig_len = 0;
  if (EVP_DigestSign(mdctx, nullptr, &sig_len, data.data(), data.size()) <= 0) {
    std::cerr << "Failed to determine signature length: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return -1;
  }

  signature.resize(sig_len);
  if (EVP_DigestSign(mdctx, signature.data(), &sig_len, data.data(),
                     data.size()) <= 0) {
    std::cerr << "Signing failed: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return -1;
  }

  signature.resize(sig_len);

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);

  return 0;
}

} // namespace shoid
