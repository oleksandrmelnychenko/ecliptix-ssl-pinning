#!/bin/bash

# Ecliptix Security PKI Generation Script
# Generates complete PKI infrastructure for SSL pinning
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATED_DIR="${SCRIPT_DIR}/generated"
DAYS_VALID=3650  # 10 years

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create directories
mkdir -p "${GENERATED_DIR}"
cd "${GENERATED_DIR}"

log_info "Starting Ecliptix PKI generation..."

# Generate Root CA private key (P-384 for maximum security)
log_info "Generating Root CA private key..."
openssl ecparam -genkey -name secp384r1 -out ecliptix_root_ca_private.pem

# Generate Root CA certificate
log_info "Generating Root CA certificate..."
openssl req -new -x509 -days ${DAYS_VALID} \
    -key ecliptix_root_ca_private.pem \
    -out ecliptix_root_ca_cert.pem \
    -subj "/C=US/ST=California/L=San Francisco/O=Ecliptix Security/OU=Root CA/CN=Ecliptix Root CA" \
    -extensions v3_ca \
    -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
[req_distinguished_name]
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

# Generate Intermediate CA private key
log_info "Generating Intermediate CA private key..."
openssl ecparam -genkey -name secp384r1 -out ecliptix_intermediate_ca_private.pem

# Generate Intermediate CA certificate request
log_info "Generating Intermediate CA certificate request..."
openssl req -new -key ecliptix_intermediate_ca_private.pem \
    -out ecliptix_intermediate_ca.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Ecliptix Security/OU=Intermediate CA/CN=Ecliptix Intermediate CA"

# Sign Intermediate CA certificate with Root CA
log_info "Signing Intermediate CA certificate..."
openssl x509 -req -in ecliptix_intermediate_ca.csr \
    -CA ecliptix_root_ca_cert.pem \
    -CAkey ecliptix_root_ca_private.pem \
    -CAcreateserial \
    -out ecliptix_intermediate_ca_cert.pem \
    -days ${DAYS_VALID} \
    -extensions v3_intermediate_ca \
    -extfile <(cat <<EOF
[v3_intermediate_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

# Generate Server private key
log_info "Generating Server private key..."
openssl ecparam -genkey -name secp384r1 -out ecliptix_server_private.pem

# Generate Server public key
log_info "Extracting Server public key..."
openssl ec -in ecliptix_server_private.pem -pubout -out ecliptix_server_public.pem

# Generate Server certificate request
log_info "Generating Server certificate request..."
openssl req -new -key ecliptix_server_private.pem \
    -out ecliptix_server.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Ecliptix Security/OU=Server/CN=ecliptix.secure"

# Sign Server certificate with Intermediate CA
log_info "Signing Server certificate..."
openssl x509 -req -in ecliptix_server.csr \
    -CA ecliptix_intermediate_ca_cert.pem \
    -CAkey ecliptix_intermediate_ca_private.pem \
    -CAcreateserial \
    -out ecliptix_server_cert.pem \
    -days ${DAYS_VALID} \
    -extensions v3_server \
    -extfile <(cat <<EOF
[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = ecliptix.secure
DNS.2 = *.ecliptix.secure
DNS.3 = api.ecliptix.secure
DNS.4 = secure.ecliptix.com
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

# Create certificate chain
log_info "Creating certificate chain..."
cat ecliptix_server_cert.pem ecliptix_intermediate_ca_cert.pem ecliptix_root_ca_cert.pem > ecliptix_cert_chain.pem

# Generate Client certificate for mutual TLS (optional)
log_info "Generating Client certificate..."
openssl ecparam -genkey -name secp384r1 -out ecliptix_client_private.pem
openssl req -new -key ecliptix_client_private.pem \
    -out ecliptix_client.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Ecliptix Security/OU=Client/CN=Ecliptix Client"

openssl x509 -req -in ecliptix_client.csr \
    -CA ecliptix_intermediate_ca_cert.pem \
    -CAkey ecliptix_intermediate_ca_private.pem \
    -CAcreateserial \
    -out ecliptix_client_cert.pem \
    -days ${DAYS_VALID} \
    -extensions v3_client \
    -extfile <(cat <<EOF
[v3_client]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

# Generate backup keys for key rotation
log_info "Generating backup keys for rotation..."
for i in {1..3}; do
    log_info "Generating backup key set ${i}..."
    openssl ecparam -genkey -name secp384r1 -out "ecliptix_backup_${i}_private.pem"
    openssl ec -in "ecliptix_backup_${i}_private.pem" -pubout -out "ecliptix_backup_${i}_public.pem"

    # Generate backup certificate
    openssl req -new -key "ecliptix_backup_${i}_private.pem" \
        -out "ecliptix_backup_${i}.csr" \
        -subj "/C=US/ST=California/L=San Francisco/O=Ecliptix Security/OU=Backup ${i}/CN=ecliptix.backup${i}"

    openssl x509 -req -in "ecliptix_backup_${i}.csr" \
        -CA ecliptix_intermediate_ca_cert.pem \
        -CAkey ecliptix_intermediate_ca_private.pem \
        -CAcreateserial \
        -out "ecliptix_backup_${i}_cert.pem" \
        -days ${DAYS_VALID} \
        -extensions v3_server \
        -extfile <(cat <<EOF
[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = ecliptix.backup${i}
DNS.2 = backup${i}.ecliptix.secure
EOF
)
done

# Generate Ed25519 keys for digital signatures
log_info "Generating Ed25519 signature keys..."
openssl genpkey -algorithm Ed25519 -out ecliptix_ed25519_private.pem
openssl pkey -in ecliptix_ed25519_private.pem -pubout -out ecliptix_ed25519_public.pem

# Generate additional Ed25519 backup keys
for i in {1..2}; do
    openssl genpkey -algorithm Ed25519 -out "ecliptix_ed25519_backup_${i}_private.pem"
    openssl pkey -in "ecliptix_ed25519_backup_${i}_private.pem" -pubout -out "ecliptix_ed25519_backup_${i}_public.pem"
done

# Extract public key pins (HPKP style)
log_info "Extracting public key pins..."

# Primary server key pin
openssl x509 -in ecliptix_server_cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64 > ecliptix_server_pin_sha256.txt

openssl x509 -in ecliptix_server_cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha384 -binary > ecliptix_server_pin_sha384.bin

# Backup key pins
for i in {1..3}; do
    openssl x509 -in "ecliptix_backup_${i}_cert.pem" -pubkey -noout | \
        openssl pkey -pubin -outform der | \
        openssl dgst -sha384 -binary > "ecliptix_backup_${i}_pin_sha384.bin"
done

# Generate SPKI pins for certificate transparency
log_info "Generating SPKI pins..."
openssl x509 -in ecliptix_server_cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der > ecliptix_server_spki.der

# Create DER format certificates for embedding
log_info "Converting certificates to DER format..."
openssl x509 -in ecliptix_server_cert.pem -outform der -out ecliptix_server_cert.der
openssl x509 -in ecliptix_intermediate_ca_cert.pem -outform der -out ecliptix_intermediate_ca_cert.der
openssl x509 -in ecliptix_root_ca_cert.pem -outform der -out ecliptix_root_ca_cert.der

# Convert keys to DER format
openssl ec -in ecliptix_server_private.pem -outform der -out ecliptix_server_private.der
openssl pkey -in ecliptix_server_public.pem -pubin -outform der -out ecliptix_server_public.der

# Generate key fingerprints for verification
log_info "Generating key fingerprints..."
openssl x509 -in ecliptix_server_cert.pem -fingerprint -sha256 -noout > ecliptix_server_fingerprint_sha256.txt
openssl x509 -in ecliptix_server_cert.pem -fingerprint -sha384 -noout > ecliptix_server_fingerprint_sha384.txt
openssl x509 -in ecliptix_server_cert.pem -fingerprint -sha512 -noout > ecliptix_server_fingerprint_sha512.txt

# Verify certificate chain
log_info "Verifying certificate chain..."
if openssl verify -CAfile ecliptix_root_ca_cert.pem -untrusted ecliptix_intermediate_ca_cert.pem ecliptix_server_cert.pem; then
    log_success "Certificate chain verification passed!"
else
    log_error "Certificate chain verification failed!"
    exit 1
fi

# Generate certificate info
log_info "Generating certificate information..."
openssl x509 -in ecliptix_server_cert.pem -text -noout > ecliptix_server_cert_info.txt
openssl x509 -in ecliptix_root_ca_cert.pem -text -noout > ecliptix_root_ca_cert_info.txt

# Secure permissions on private keys
log_info "Setting secure permissions on private keys..."
chmod 600 *.pem
find . -name "*.der" -exec chmod 644 {} \; 2>/dev/null || true
find . -name "*.txt" -exec chmod 644 {} \; 2>/dev/null || true
find . -name "*.bin" -exec chmod 644 {} \; 2>/dev/null || true

# Create key summary
cat > key_summary.txt <<EOF
Ecliptix Security PKI Summary
=============================
Generated on: $(date)

Certificate Authority:
- Root CA: ecliptix_root_ca_cert.pem
- Intermediate CA: ecliptix_intermediate_ca_cert.pem

Server Certificate:
- Certificate: ecliptix_server_cert.pem
- Private Key: ecliptix_server_private.pem
- Public Key: ecliptix_server_public.pem
- Certificate Chain: ecliptix_cert_chain.pem

Client Certificate:
- Certificate: ecliptix_client_cert.pem
- Private Key: ecliptix_client_private.pem

Backup Keys (for rotation):
- Backup 1: ecliptix_backup_1_cert.pem / ecliptix_backup_1_private.pem
- Backup 2: ecliptix_backup_2_cert.pem / ecliptix_backup_2_private.pem
- Backup 3: ecliptix_backup_3_cert.pem / ecliptix_backup_3_private.pem

Ed25519 Signature Keys:
- Primary: ecliptix_ed25519_private.pem / ecliptix_ed25519_public.pem
- Backup 1: ecliptix_ed25519_backup_1_private.pem / ecliptix_ed25519_backup_1_public.pem
- Backup 2: ecliptix_ed25519_backup_2_private.pem / ecliptix_ed25519_backup_2_public.pem

Public Key Pins (SHA-384):
- Primary: ecliptix_server_pin_sha384.bin
- Backup 1: ecliptix_backup_1_pin_sha384.bin
- Backup 2: ecliptix_backup_2_pin_sha384.bin
- Backup 3: ecliptix_backup_3_pin_sha384.bin

Usage:
- Use ecliptix_cert_chain.pem for server configuration
- Use ecliptix_server_pin_sha384.bin for SSL pinning in client
- Use backup pins for key rotation without app updates
- Use Ed25519 keys for digital signatures
EOF

log_success "PKI generation completed successfully!"
log_info "Generated files are in: ${GENERATED_DIR}"
log_info "Key summary: ${GENERATED_DIR}/key_summary.txt"

# Clean up temporary files
rm -f *.csr *.srl

log_success "Ecliptix PKI generation complete!"