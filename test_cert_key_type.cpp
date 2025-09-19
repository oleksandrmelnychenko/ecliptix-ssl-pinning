#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "embedded/embedded_keys.hpp"

static void deobfuscate_data(std::vector<uint8_t>& data, uint8_t xor_key) {
    for (auto& byte : data) {
        byte ^= xor_key;
    }
}

int main() {
    std::cout << "Checking embedded certificate key type..." << std::endl;

    // Get embedded certificate data
    auto cert_der = ecliptix::embedded::SERVER_CERT_DER;
    std::vector<uint8_t> cert_data(cert_der.begin(), cert_der.end());

    // Deobfuscate
    deobfuscate_data(cert_data, ecliptix::embedded::CERT_XOR_KEY);

    // Parse certificate
    const unsigned char* cert_ptr = cert_data.data();
    X509* cert = d2i_X509(nullptr, &cert_ptr, cert_data.size());

    if (!cert) {
        std::cout << "Failed to parse certificate" << std::endl;
        return 1;
    }

    // Get public key
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        std::cout << "Failed to get public key from certificate" << std::endl;
        X509_free(cert);
        return 1;
    }

    // Check key type
    int key_type = EVP_PKEY_id(pkey);

    std::cout << "Key type ID: " << key_type << std::endl;

    // Check specific types
    if (key_type == EVP_PKEY_RSA) {
        std::cout << "✓ RSA key found" << std::endl;
    } else if (key_type == EVP_PKEY_EC) {
        std::cout << "✓ ECDSA key found" << std::endl;
        std::cout << "  This explains why RSA encryption fails!" << std::endl;
    } else if (key_type == EVP_PKEY_ED25519) {
        std::cout << "✓ Ed25519 key found" << std::endl;
    } else {
        std::cout << "✗ Unknown key type: " << key_type << std::endl;
    }

    EVP_PKEY_free(pkey);
    X509_free(cert);

    return 0;
}