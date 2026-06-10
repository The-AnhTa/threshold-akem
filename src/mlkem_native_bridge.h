#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    RMTLS_MLKEM512_PUBLIC_KEY_BYTES = 800,
    RMTLS_MLKEM512_SECRET_KEY_BYTES = 1632,
    RMTLS_MLKEM512_CIPHERTEXT_BYTES = 768,
    RMTLS_MLKEM512_SHARED_SECRET_BYTES = 32,
    RMTLS_MLKEM512_MESSAGE_BYTES = 32,
    RMTLS_MLKEM512_S_HAT_COEFFICIENTS = 512,
    RMTLS_MLKEM512_INNER_COEFFICIENTS = 256
};

int rmtls_mlkem512_keypair(
    uint8_t public_key[RMTLS_MLKEM512_PUBLIC_KEY_BYTES],
    uint8_t secret_key[RMTLS_MLKEM512_SECRET_KEY_BYTES]);

int rmtls_mlkem512_encapsulate(
    uint8_t ciphertext[RMTLS_MLKEM512_CIPHERTEXT_BYTES],
    uint8_t shared_secret[RMTLS_MLKEM512_SHARED_SECRET_BYTES],
    const uint8_t public_key[RMTLS_MLKEM512_PUBLIC_KEY_BYTES]);

int rmtls_mlkem512_decapsulate(
    uint8_t shared_secret[RMTLS_MLKEM512_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[RMTLS_MLKEM512_CIPHERTEXT_BYTES],
    const uint8_t secret_key[RMTLS_MLKEM512_SECRET_KEY_BYTES]);

int rmtls_mlkem512_extract_s_hat(
    uint16_t output[RMTLS_MLKEM512_S_HAT_COEFFICIENTS],
    const uint8_t secret_key[RMTLS_MLKEM512_SECRET_KEY_BYTES]);

int rmtls_mlkem512_dec_msg(
    uint8_t message[RMTLS_MLKEM512_MESSAGE_BYTES],
    const uint16_t s_hat[RMTLS_MLKEM512_S_HAT_COEFFICIENTS],
    const uint8_t ciphertext[RMTLS_MLKEM512_CIPHERTEXT_BYTES]);

int rmtls_mlkem512_public_u_hat(
    uint16_t output[RMTLS_MLKEM512_S_HAT_COEFFICIENTS],
    const uint8_t ciphertext[RMTLS_MLKEM512_CIPHERTEXT_BYTES]);

int rmtls_mlkem512_assistant_inner(
    uint16_t output[RMTLS_MLKEM512_INNER_COEFFICIENTS],
    const uint16_t share[RMTLS_MLKEM512_S_HAT_COEFFICIENTS],
    const uint8_t ciphertext[RMTLS_MLKEM512_CIPHERTEXT_BYTES]);

int rmtls_mlkem512_dec_msg_from_combined(
    uint8_t message[RMTLS_MLKEM512_MESSAGE_BYTES],
    const uint16_t combined[RMTLS_MLKEM512_INNER_COEFFICIENTS],
    const uint8_t ciphertext[RMTLS_MLKEM512_CIPHERTEXT_BYTES]);

int rmtls_mlkem512_fo_validate(
    uint8_t shared_secret[RMTLS_MLKEM512_SHARED_SECRET_BYTES],
    const uint8_t message[RMTLS_MLKEM512_MESSAGE_BYTES],
    const uint8_t ciphertext[RMTLS_MLKEM512_CIPHERTEXT_BYTES],
    const uint8_t public_key[RMTLS_MLKEM512_PUBLIC_KEY_BYTES],
    const uint8_t fallback_secret[RMTLS_MLKEM512_SHARED_SECRET_BYTES]);

void rmtls_sha3_256(
    uint8_t output[32],
    const uint8_t* input,
    size_t input_length);

void rmtls_shake256(
    uint8_t* output,
    size_t output_length,
    const uint8_t* input,
    size_t input_length);

#ifdef __cplusplus
}
#endif
