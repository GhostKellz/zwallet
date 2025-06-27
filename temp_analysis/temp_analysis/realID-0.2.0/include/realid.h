#ifndef REALID_H
#define REALID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// RealID types
typedef struct {
    uint8_t bytes[64];
} RealIDPrivateKey;

typedef struct {
    uint8_t bytes[32];
} RealIDPublicKey;

typedef struct {
    RealIDPrivateKey private_key;
    RealIDPublicKey public_key;
} RealIDKeyPair;

typedef struct {
    uint8_t bytes[64];
} RealIDSignature;

typedef struct {
    uint8_t bytes[16];
} QID;

typedef struct {
    uint8_t bytes[32];
} DeviceFingerprint;

// Result codes
#define REALID_SUCCESS 0
#define REALID_ERROR_INVALID_PASSPHRASE -1
#define REALID_ERROR_INVALID_SIGNATURE -2
#define REALID_ERROR_INVALID_KEY -3
#define REALID_ERROR_CRYPTO -4
#define REALID_ERROR_MEMORY -5
#define REALID_ERROR_BUFFER_TOO_SMALL -6

// Function declarations
int realid_generate_from_passphrase_c(
    const uint8_t* passphrase,
    size_t passphrase_len,
    RealIDKeyPair* keypair_out
);

int realid_generate_from_passphrase_with_device_c(
    const uint8_t* passphrase,
    size_t passphrase_len,
    const DeviceFingerprint* device_fingerprint,
    RealIDKeyPair* keypair_out
);

int realid_sign_c(
    const uint8_t* data,
    size_t data_len,
    const RealIDPrivateKey* private_key,
    RealIDSignature* signature_out
);

int realid_verify_c(
    const RealIDSignature* signature,
    const uint8_t* data,
    size_t data_len,
    const RealIDPublicKey* public_key
);

int realid_qid_from_pubkey_c(
    const RealIDPublicKey* public_key,
    QID* qid_out
);

int realid_generate_device_fingerprint_c(
    DeviceFingerprint* fingerprint_out
);

int realid_get_public_key_c(
    const RealIDPrivateKey* private_key,
    RealIDPublicKey* public_key_out
);

int realid_qid_to_string_c(
    const QID* qid,
    uint8_t* buffer,
    size_t buffer_len,
    size_t* written_len
);

#ifdef __cplusplus
}
#endif

#endif // REALID_H
