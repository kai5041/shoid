#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <shoid/ed25519.hpp>

namespace shoid {

int ed25519_generate_keypair(std::vector<std::string> args) {
  if (args.empty()) {
    std::cerr << "Missing output directory argument.\n";
    return 1;
  }
  return __ed25519_generate_keypair(args[0]);
}

static std::string bio_to_string(BIO *bio) {
  BUF_MEM *mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  return std::string(mem->data, mem->length);
}

int __ed25519_generate_keypair(const std::string &output_dir) {
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

  BIO *bio_priv = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr,
                                nullptr)) {
    std::cerr << "Failed to encode private key: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    BIO_free(bio_priv);
    EVP_PKEY_free(pkey);
    return 1;
  }

  std::string priv_pem = bio_to_string(bio_priv);
  BIO_free(bio_priv);

  BIO *bio_pub = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_PUBKEY(bio_pub, pkey)) {
    std::cerr << "Failed to encode public key: "
              << ERR_error_string(ERR_get_error(), nullptr) << "\n";
    BIO_free(bio_pub);
    EVP_PKEY_free(pkey);
    return 1;
  }

  std::string pub_pem = bio_to_string(bio_pub);
  BIO_free(bio_pub);

  try {
    std::string priv_path = output_dir + "/ed25519_private.pem";
    int fd_priv = open(priv_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd_priv < 0) {
      perror("open");
      EVP_PKEY_free(pkey);
      return 1;
    }
    std::string pub_path = output_dir + "/ed25519_public.pem";
    int fd_pub = open(pub_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd_pub < 0) {
      perror("open");
      EVP_PKEY_free(pkey);
      return 1;
    }
    std::ofstream priv_out;
    priv_out.open(priv_path, std::ios::out | std::ios::trunc);
    priv_out << priv_pem;
    priv_out.flush();
    priv_out.close();

    std::ofstream pub_out;
    pub_out.open(pub_path, std::ios::out | std::ios::trunc);
    pub_out << pub_pem;
    pub_out.flush();
    pub_out.close();

    close(fd_priv);
    close(fd_pub);
  } catch (const std::ofstream::failure &e) {
    std::cerr << "Failed to write PEM files: " << e.what() << "\n";
    EVP_PKEY_free(pkey);
    return 1;
  }

  OPENSSL_cleanse(priv_pem.data(), priv_pem.size());

  EVP_PKEY_free(pkey);
  std::cout << "Ed25519 keypair generated successfully in: " << output_dir
            << "\n";
  return 0;
}

} // namespace shoid
