#include "ecliptix_server.h"
#include "../embedded/keys.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cstring>

#ifdef _WIN32
  #define ECLIPTIX_API __declspec(dllexport)
#else
  #define ECLIPTIX_API __attribute__((visibility("default")))
#endif


static const char* g_last_error = nullptr;
static EVP_PKEY* g_server_private_key = nullptr;
static EVP_PKEY* g_client_public_key = nullptr;

static void set_error(const char* error) {
    g_last_error = error;
}

static EVP_PKEY* load_server_private_key() {
    BIO* bio = BIO_new_mem_buf(SERVER_PRIVATE_KEY_PEM, SERVER_PRIVATE_KEY_PEM_size);
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

static EVP_PKEY* load_server_private_key_from_pem(const uint8_t* private_key_pem, size_t key_size) {
    if (!private_key_pem || key_size == 0) {
        return nullptr;
    }

    BIO* bio = BIO_new_mem_buf(private_key_pem, static_cast<int>(key_size));
    if (!bio) {
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (key) {
        EVP_PKEY_CTX* test_ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!test_ctx) {
            EVP_PKEY_free(key);
            return nullptr;
        }
        EVP_PKEY_CTX_free(test_ctx);
    }

    return key;
}

static EVP_PKEY* load_client_public_key() {
    BIO* bio = BIO_new_mem_buf(CLIENT_PUBLIC_KEY_PEM, CLIENT_PUBLIC_KEY_SIZE);
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

int ecliptix_server_init(void) {
    if (g_server_private_key) return ECLIPTIX_SUCCESS;

    g_server_private_key = load_server_private_key();
    g_client_public_key = load_client_public_key();

    if (!g_server_private_key || !g_client_public_key) {
        set_error("Failed to load keys");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    set_error(nullptr);
    return ECLIPTIX_SUCCESS;
}

int ecliptix_server_init_with_key(const uint8_t* private_key_pem, size_t key_size) {
    if (!private_key_pem || key_size == 0) {
        set_error("Invalid private key parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (g_server_private_key) {
        set_error("Server already initialized");
        return ECLIPTIX_SUCCESS;
    }

    g_server_private_key = load_server_private_key_from_pem(private_key_pem, key_size);
    g_client_public_key = load_client_public_key();

    if (!g_server_private_key) {
        set_error("Failed to load provided private key - invalid format or corrupted");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    if (!g_client_public_key) {
        set_error("Failed to load client public key");
        EVP_PKEY_free(g_server_private_key);
        g_server_private_key = nullptr;
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    set_error(nullptr);
    return ECLIPTIX_SUCCESS;
}

int ecliptix_server_init_with_keys(const uint8_t* server_private_pem, size_t server_key_size,
                                   const uint8_t* client_public_pem, size_t client_pub_size) {
    if (!server_private_pem || server_key_size == 0 || !client_public_pem || client_pub_size == 0) {
        set_error("Invalid key parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (g_server_private_key || g_client_public_key) {
        set_error("Server already initialized");
        return ECLIPTIX_SUCCESS;
    }

    g_server_private_key = load_server_private_key_from_pem(server_private_pem, server_key_size);

    BIO* bio = BIO_new_mem_buf(client_public_pem, static_cast<int>(client_pub_size));
    if (bio) {
        g_client_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    }

    if (!g_server_private_key) {
        set_error("Failed to load provided server private key");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    if (!g_client_public_key) {
        set_error("Failed to load provided client public key");
        EVP_PKEY_free(g_server_private_key);
        g_server_private_key = nullptr;
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    set_error(nullptr);
    return ECLIPTIX_SUCCESS;
}

void ecliptix_server_cleanup(void) {
    if (g_server_private_key) {
        EVP_PKEY_free(g_server_private_key);
        g_server_private_key = nullptr;
    }
    if (g_client_public_key) {
        EVP_PKEY_free(g_client_public_key);
        g_client_public_key = nullptr;
    }
}

ecliptix_result_t ecliptix_server_encrypt(
    const uint8_t* plaintext,
    size_t plain_len,
    uint8_t* ciphertext,
    size_t* cipher_len
) {
    if (!ciphertext || !cipher_len) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!plaintext && plain_len > 0) {
        set_error("Invalid parameters: non-null data required when plain_len > 0");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_client_public_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    int key_size = EVP_PKEY_size(g_client_public_key);
    if (key_size <= 0 || *cipher_len < static_cast<size_t>(key_size)) {
        set_error("Buffer too small for encryption output");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(g_client_public_key, nullptr);
    if (!ctx) {
        set_error("Failed to create context");
        return ECLIPTIX_ERROR_CRYPTO_FAILURE;
    }

    ecliptix_result_t result = ECLIPTIX_ERROR_CRYPTO_FAILURE;
    if (EVP_PKEY_encrypt_init(ctx) == 1) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            size_t out_len = *cipher_len;
            if (EVP_PKEY_encrypt(ctx, ciphertext, &out_len, plaintext, plain_len) == 1) {
                *cipher_len = out_len;
                result = ECLIPTIX_SUCCESS;
                set_error(nullptr);
            } else {
                set_error("Encryption failed");
            }
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

ecliptix_result_t ecliptix_server_decrypt(
    const uint8_t* ciphertext,
    size_t cipher_len,
    uint8_t* plaintext,
    size_t* plain_len
) {
    if (!ciphertext || !plaintext || !plain_len) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_server_private_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(g_server_private_key, nullptr);
    if (!ctx) {
        set_error("Failed to create context");
        return ECLIPTIX_ERROR_CRYPTO_FAILURE;
    }

    ecliptix_result_t result = ECLIPTIX_ERROR_CRYPTO_FAILURE;
    if (EVP_PKEY_decrypt_init(ctx) == 1) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            size_t out_len = *plain_len;
            if (EVP_PKEY_decrypt(ctx, plaintext, &out_len, ciphertext, cipher_len) == 1) {
                *plain_len = out_len;
                result = ECLIPTIX_SUCCESS;
                set_error(nullptr);
            } else {
                set_error("Decryption failed");
            }
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

ecliptix_result_t ecliptix_server_sign(
    const uint8_t* data,
    size_t data_len,
    uint8_t* signature,
    size_t* sig_len
) {
    if (!signature || !sig_len) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!data && data_len > 0) {
        set_error("Invalid parameters: non-null data required when data_len > 0");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_server_private_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        set_error("Failed to create context");
        return ECLIPTIX_ERROR_CRYPTO_FAILURE;
    }

    ecliptix_result_t result = ECLIPTIX_ERROR_CRYPTO_FAILURE;
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, g_server_private_key) == 1) {
        if (EVP_DigestSignUpdate(ctx, data, data_len) == 1) {
            size_t out_len = *sig_len;
            if (EVP_DigestSignFinal(ctx, signature, &out_len) == 1) {
                *sig_len = out_len;
                result = ECLIPTIX_SUCCESS;
                set_error(nullptr);
            } else {
                set_error("Signing failed");
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

const char* ecliptix_server_get_error(void) {
    return g_last_error ? g_last_error : "No error";
}