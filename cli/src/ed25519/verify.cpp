#include "shoid/ed25519.hpp"
#include <fstream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <vector>

namespace shoid {

int ed25519_verify(std::vector<std::string> args) {
  if (args.size() != 3) {
    std::cerr << "Usage: " << args[0]
              << " <filename> <signature.sig> <public_key.pem>\n";
    return 1;
  }

  return __ed25519_verify(args[0], args[1], args[2]);
}

int __ed25519_verify(const std::string &filename, const std::string &sigfile,
                     const std::string &pubkeyfile) {
  std::ifstream file(filename, std::ios::binary);
  if (!file) {
    std::cerr << "Cannot open file: " << filename << "\n";
    return 1;
  }
  std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
  file.close();

  std::ifstream sigf(sigfile, std::ios::binary);
  if (!sigf) {
    std::cerr << "Cannot open signature file: " << sigfile << "\n";
    return 1;
  }
  std::vector<unsigned char> signature((std::istreambuf_iterator<char>(sigf)),
                                       std::istreambuf_iterator<char>());
  sigf.close();

  FILE *f = fopen(pubkeyfile.c_str(), "r");
  if (!f) {
    std::cerr << "Cannot open public key file: " << pubkeyfile << "\n";
    return 1;
  }

  EVP_PKEY *pubkey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
  fclose(f);
  if (!pubkey) {
    std::cerr << "Error loading public key\n";
    ERR_print_errors_fp(stderr);
    return 1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    std::cerr << "Failed to create context\n";
    EVP_PKEY_free(pubkey);
    return 1;
  }

  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pubkey) != 1) {
    std::cerr << "DigestVerifyInit failed\n";
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return 1;
  }

  int ret = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                             data.data(), data.size());
  if (ret == 1) {
    std::cout << "Signature is VALID.\n";
  } else if (ret == 0) {
    std::cout << "Signature is INVALID.\n";
  } else {
    std::cerr << "Error during verification.\n";
    ERR_print_errors_fp(stderr);
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pubkey);
  return 0;
}

} // namespace shoid
