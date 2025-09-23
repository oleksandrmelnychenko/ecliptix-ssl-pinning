#include "ecliptix_client.h"
#include "../embedded/keys.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <cstring>

#ifdef _WIN32
#define ECLIPTIX_API __declspec(dllexport)
#else
#define ECLIPTIX_API __attribute__((visibility("default")))
#endif


static const char* g_last_error = nullptr;
static EVP_PKEY* g_server_public_key = nullptr;
static EVP_PKEY* g_client_private_key = nullptr;
static EVP_PKEY* g_client_public_key = nullptr;

static void set_error(const char* error) {
    g_last_error = error;
}

static EVP_PKEY* load_server_public_key() {
    BIO* bio = BIO_new_mem_buf(SERVER_PUBLIC_KEY_PEM, SERVER_PUBLIC_KEY_PEM_size);
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

static EVP_PKEY* load_client_private_key() {
    BIO* bio = BIO_new_mem_buf(CLIENT_PRIVATE_KEY_PEM, CLIENT_PRIVATE_KEY_PEM_size);
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

static EVP_PKEY* load_client_public_key() {
    BIO* bio = BIO_new_mem_buf(CLIENT_PUBLIC_KEY_PEM, CLIENT_PUBLIC_KEY_PEM_size);
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

int ecliptix_client_init(void) {
    if (g_server_public_key && g_client_private_key && g_client_public_key) return ECLIPTIX_SUCCESS;

    if (!g_server_public_key) {
        g_server_public_key = load_server_public_key();
        if (!g_server_public_key) {
            set_error("Failed to load server public key");
            return ECLIPTIX_ERROR_INIT_FAILED;
        }
    }

    if (!g_client_private_key) {
        g_client_private_key = load_client_private_key();
        if (!g_client_private_key) {
            set_error("Failed to load client private key");
            return ECLIPTIX_ERROR_INIT_FAILED;
        }
    }

    if (!g_client_public_key) {
        g_client_public_key = load_client_public_key();
        if (!g_client_public_key) {
            set_error("Failed to load client public key");
            return ECLIPTIX_ERROR_INIT_FAILED;
        }
    }

    set_error(nullptr);
    return ECLIPTIX_SUCCESS;
}

void ecliptix_client_cleanup(void) {
    if (g_server_public_key) {
        EVP_PKEY_free(g_server_public_key);
        g_server_public_key = nullptr;
    }
    if (g_client_private_key) {
        EVP_PKEY_free(g_client_private_key);
        g_client_private_key = nullptr;
    }
    if (g_client_public_key) {
        EVP_PKEY_free(g_client_public_key);
        g_client_public_key = nullptr;
    }
}

ecliptix_result_t ecliptix_client_verify(
    const uint8_t* data,
    size_t data_len,
    const uint8_t* signature,
    size_t sig_len
) {
    if (!signature) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!data && data_len > 0) {
        set_error("Invalid parameters: non-null data required when data_len > 0");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_server_public_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        set_error("Failed to create context");
        return ECLIPTIX_ERROR_CRYPTO_FAILURE;
    }

    ecliptix_result_t result = ECLIPTIX_ERROR_CRYPTO_FAILURE;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, g_server_public_key) == 1) {
        if (EVP_DigestVerifyUpdate(ctx, data, data_len) == 1) {
            if (EVP_DigestVerifyFinal(ctx, signature, sig_len) == 1) {
                result = ECLIPTIX_SUCCESS;
                set_error(nullptr);
            } else {
                set_error("Verification failed");
                result = ECLIPTIX_ERROR_VERIFICATION_FAILED;
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

ecliptix_result_t ecliptix_client_encrypt(
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
) {
    if (!plaintext || !ciphertext || !ciphertext_len) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_client_public_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(g_client_public_key, nullptr);
    if (!ctx) {
        set_error("Failed to create encryption context");
        return ECLIPTIX_ERROR_CRYPTO_FAILURE;
    }

    ecliptix_result_t result = ECLIPTIX_ERROR_CRYPTO_FAILURE;
    if (EVP_PKEY_encrypt_init(ctx) == 1) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            if (EVP_PKEY_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len) == 1) {
                result = ECLIPTIX_SUCCESS;
                set_error(nullptr);
            } else {
                set_error("Encryption failed");
            }
        } else {
            set_error("Failed to set RSA padding");
        }
    } else {
        set_error("Failed to initialize encryption");
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

ecliptix_result_t ecliptix_client_decrypt(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
) {
    if (!ciphertext || !plaintext || !plaintext_len) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_client_private_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(g_client_private_key, nullptr);
    if (!ctx) {
        set_error("Failed to create decryption context");
        return ECLIPTIX_ERROR_CRYPTO_FAILURE;
    }

    ecliptix_result_t result = ECLIPTIX_ERROR_CRYPTO_FAILURE;
    if (EVP_PKEY_decrypt_init(ctx) == 1) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            if (EVP_PKEY_decrypt(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len) == 1) {
                result = ECLIPTIX_SUCCESS;
                set_error(nullptr);
            } else {
                set_error("Decryption failed");
            }
        } else {
            set_error("Failed to set RSA padding");
        }
    } else {
        set_error("Failed to initialize decryption");
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

ecliptix_result_t ecliptix_client_get_public_key(
    uint8_t* public_key_der,
    size_t* public_key_len
) {
    if (!public_key_der || !public_key_len) {
        set_error("Invalid parameters");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    if (!g_client_public_key) {
        set_error("Not initialized");
        return ECLIPTIX_ERROR_INIT_FAILED;
    }

    unsigned char* der_buf = nullptr;
    int der_len = i2d_PUBKEY(g_client_public_key, &der_buf);

    if (der_len <= 0 || !der_buf) {
        set_error("Failed to encode public key");
        return ECLIPTIX_ERROR_CRYPTO_FAILURE;
    }

    if (*public_key_len < (size_t)der_len) {
        *public_key_len = der_len;
        OPENSSL_free(der_buf);
        set_error("Buffer too small");
        return ECLIPTIX_ERROR_INVALID_PARAMS;
    }

    memcpy(public_key_der, der_buf, der_len);
    *public_key_len = der_len;
    OPENSSL_free(der_buf);

    set_error(nullptr);
    return ECLIPTIX_SUCCESS;
}

const char* ecliptix_client_get_error(void) {
    return g_last_error ? g_last_error : "No error";
}