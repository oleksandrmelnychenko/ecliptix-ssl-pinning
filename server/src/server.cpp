#include "ecliptix_server.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cstring>

#ifdef _WIN32
  #define ECLIPTIX_API __declspec(dllexport)
#else
  #define ECLIPTIX_API __attribute__((visibility("default")))
#endif

static const unsigned char CLIENT_PUBLIC_KEY_PEM[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x42, 0x49, 0x6a, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x4f, 0x43, 0x41, 0x51, 0x38, 0x41, 0x4d, 0x49, 0x49, 0x42, 0x43, 0x67, 0x4b, 0x43, 0x41, 0x51, 0x45, 0x41, 0x32, 0x6e, 0x70, 0x68, 0x64, 0x45, 0x74, 0x53, 0x78, 0x79, 0x4d, 0x4b, 0x69, 0x6b, 0x78, 0x33, 0x6f, 0x57, 0x2f, 0x68, 0x0a, 0x44, 0x37, 0x37, 0x48, 0x6e, 0x44, 0x5a, 0x69, 0x46, 0x4f, 0x5a, 0x54, 0x74, 0x44, 0x49, 0x73, 0x6b, 0x52, 0x72, 0x62, 0x74, 0x72, 0x34, 0x7a, 0x66, 0x32, 0x44, 0x7a, 0x72, 0x46, 0x30, 0x4b, 0x6d, 0x39, 0x4b, 0x58, 0x79, 0x76, 0x4e, 0x44, 0x4c, 0x71, 0x35, 0x6d, 0x46, 0x41, 0x44, 0x41, 0x31, 0x65, 0x4e, 0x76, 0x50, 0x51, 0x56, 0x61, 0x76, 0x78, 0x46, 0x55, 0x4e, 0x2b, 0x31, 0x4d, 0x0a, 0x55, 0x37, 0x50, 0x2b, 0x46, 0x2b, 0x6c, 0x48, 0x7a, 0x45, 0x49, 0x6a, 0x51, 0x4c, 0x5a, 0x57, 0x43, 0x63, 0x78, 0x68, 0x31, 0x54, 0x30, 0x74, 0x49, 0x6e, 0x4a, 0x57, 0x43, 0x48, 0x42, 0x51, 0x52, 0x67, 0x42, 0x32, 0x4d, 0x67, 0x45, 0x72, 0x34, 0x43, 0x6f, 0x37, 0x4a, 0x2f, 0x64, 0x70, 0x76, 0x73, 0x5a, 0x47, 0x61, 0x5a, 0x74, 0x4a, 0x75, 0x66, 0x62, 0x4b, 0x65, 0x33, 0x34, 0x46, 0x0a, 0x6a, 0x59, 0x72, 0x61, 0x39, 0x51, 0x50, 0x78, 0x6f, 0x67, 0x6b, 0x78, 0x4a, 0x7a, 0x66, 0x63, 0x73, 0x63, 0x4c, 0x31, 0x4f, 0x55, 0x6c, 0x6a, 0x35, 0x64, 0x77, 0x77, 0x65, 0x64, 0x6b, 0x31, 0x7a, 0x42, 0x63, 0x77, 0x66, 0x75, 0x58, 0x6d, 0x35, 0x75, 0x54, 0x6f, 0x4f, 0x54, 0x7a, 0x6f, 0x45, 0x69, 0x6b, 0x30, 0x4a, 0x5a, 0x78, 0x7a, 0x45, 0x53, 0x4f, 0x4e, 0x61, 0x4a, 0x62, 0x6d, 0x0a, 0x4a, 0x58, 0x38, 0x67, 0x32, 0x6a, 0x6a, 0x4b, 0x76, 0x72, 0x78, 0x35, 0x39, 0x48, 0x48, 0x4f, 0x68, 0x70, 0x4a, 0x48, 0x68, 0x73, 0x71, 0x72, 0x30, 0x6f, 0x74, 0x4a, 0x37, 0x49, 0x50, 0x70, 0x72, 0x75, 0x59, 0x6a, 0x63, 0x75, 0x79, 0x31, 0x59, 0x66, 0x6d, 0x50, 0x69, 0x54, 0x7a, 0x37, 0x72, 0x44, 0x71, 0x44, 0x64, 0x78, 0x71, 0x61, 0x37, 0x6d, 0x39, 0x47, 0x4f, 0x41, 0x58, 0x74, 0x0a, 0x35, 0x7a, 0x30, 0x53, 0x67, 0x49, 0x67, 0x57, 0x69, 0x48, 0x2b, 0x41, 0x78, 0x4a, 0x79, 0x75, 0x61, 0x78, 0x53, 0x76, 0x45, 0x7a, 0x35, 0x5a, 0x48, 0x4c, 0x6b, 0x6f, 0x50, 0x67, 0x6d, 0x4c, 0x44, 0x38, 0x6e, 0x4c, 0x66, 0x75, 0x59, 0x5a, 0x2f, 0x4c, 0x4f, 0x52, 0x63, 0x73, 0x44, 0x74, 0x43, 0x66, 0x34, 0x31, 0x34, 0x6c, 0x64, 0x46, 0x7a, 0x46, 0x5a, 0x41, 0x62, 0x59, 0x46, 0x6d, 0x0a, 0x5a, 0x51, 0x49, 0x44, 0x41, 0x51, 0x41, 0x42, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
};
static const size_t CLIENT_PUBLIC_KEY_PEM_size = 451;
#define CLIENT_PUBLIC_KEY_SIZE CLIENT_PUBLIC_KEY_PEM_size

static const char* g_last_error = nullptr;
static EVP_PKEY* g_server_private_key = nullptr;
static EVP_PKEY* g_client_public_key = nullptr;

static void set_error(const char* error) {
    g_last_error = error;
}

static EVP_PKEY* load_server_private_key() {
    return nullptr;
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
    if (!plaintext || !ciphertext || !cipher_len) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_client_public_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
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
    if (!data || !signature || !sig_len) {
        set_error("Invalid parameters");
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