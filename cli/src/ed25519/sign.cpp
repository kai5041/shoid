#include <fstream>
#include <iostream>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <vector>

#include <shoid/ed25519.hpp>

namespace shoid {

int ed25519_sign(std::vector<std::string> args) {
  if (args.size() != 3) {
    std::cerr << "Usage: " << args[0]
              << " <filename> <private_key.pem> <output.sig>\n";
    return 1;
  }

  return __ed25519_sign(args[0], args[1], args[2]);
}

int __ed25519_sign(const std::string &filename, const std::string &keyfile,
                   const std::string &sigfile) {

  std::ifstream file(filename, std::ios::binary);
  if (!file) {
    std::cerr << "Cannot open file: " << filename << "\n";
    return 1;
  }
  std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
  file.close();

  FILE *f = fopen(keyfile.c_str(), "r");
  if (!f) {
    std::cerr << "Cannot open key file: " << keyfile << "\n";
    return 1;
  }
  EVP_PKEY *pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
  fclose(f);
  if (!pkey) {
    std::cerr << "Error loading private key\n";
    ERR_print_errors_fp(stderr);
    return 1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    std::cerr << "Failed to create context\n";
    EVP_PKEY_free(pkey);
    return 1;
  }

  if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
    std::cerr << "DigestSignInit failed\n";
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;
  }

  size_t sig_len = 0;
  if (EVP_DigestSign(ctx, nullptr, &sig_len, data.data(), data.size()) != 1) {
    std::cerr << "DigestSign (get length) failed\n";
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;
  }

  std::vector<unsigned char> signature(sig_len);
  if (EVP_DigestSign(ctx, signature.data(), &sig_len, data.data(),
                     data.size()) != 1) {
    std::cerr << "DigestSign failed\n";
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;
  }

  std::ofstream ofs(sigfile, std::ios::binary);
  if (!ofs) {
    std::cerr << "Cannot open output file: " << sigfile << "\n";
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;
  }
  ofs.write(reinterpret_cast<const char *>(signature.data()), sig_len);
  ofs.close();

  std::cout << "Signature written to " << sigfile << " (" << sig_len
            << " bytes)\n";

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return 0;
}
} // namespace shoid