#include "mlkem_native_bridge.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
#include <stdlib.h>
#else
#error "mlkem-native bridge requires an operating-system random source"
#endif

#include "src/compress.h"
#include "src/indcpa.h"
#include "src/poly.h"
#include "src/poly_k.h"
#include "src/symmetric.h"
#include "src/verify.h"

int rmtls_mlkem_keypair(uint8_t public_key[800],
                        uint8_t secret_key[1632]);
int rmtls_mlkem_enc(uint8_t ciphertext[768],
                    uint8_t shared_secret[32],
                    const uint8_t public_key[800]);
int rmtls_mlkem_dec(uint8_t shared_secret[32],
                    const uint8_t ciphertext[768],
                    const uint8_t secret_key[1632]);

static void bridge_zeroize(void* pointer, size_t length)
{
  volatile uint8_t* bytes = (volatile uint8_t*)pointer;
  size_t index;
  for (index = 0; index < length; ++index)
  {
    bytes[index] = 0;
  }
}

static uint16_t canonical_coefficient(int16_t value)
{
  int32_t result = value % MLKEM_Q;
  if (result < 0)
  {
    result += MLKEM_Q;
  }
  return (uint16_t)result;
}

void randombytes(uint8_t* output, size_t length)
{
#if defined(_WIN32)
  while (length > 0)
  {
    const ULONG chunk =
        length > (size_t)0xffffffffu ? 0xffffffffu : (ULONG)length;
    if (!BCRYPT_SUCCESS(BCryptGenRandom(
            NULL, output, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
      abort();
    }
    output += chunk;
    length -= chunk;
  }
#elif defined(__linux__)
  size_t offset = 0;
  while (offset < length)
  {
    const ssize_t received = getrandom(output + offset, length - offset, 0);
    if (received > 0)
    {
      offset += (size_t)received;
    }
    else if (received < 0 && errno == EINTR)
    {
      continue;
    }
    else
    {
      abort();
    }
  }
#else
  arc4random_buf(output, length);
#endif
}

int rmtls_mlkem512_keypair(uint8_t public_key[800],
                           uint8_t secret_key[1632])
{
  return rmtls_mlkem_keypair(public_key, secret_key);
}

int rmtls_mlkem512_encapsulate(uint8_t ciphertext[768],
                               uint8_t shared_secret[32],
                               const uint8_t public_key[800])
{
  return rmtls_mlkem_enc(ciphertext, shared_secret, public_key);
}

int rmtls_mlkem512_decapsulate(uint8_t shared_secret[32],
                               const uint8_t ciphertext[768],
                               const uint8_t secret_key[1632])
{
  return rmtls_mlkem_dec(shared_secret, ciphertext, secret_key);
}

int rmtls_mlkem512_extract_s_hat(uint16_t output[512],
                                 const uint8_t secret_key[1632])
{
  mlk_polyvec secret;
  size_t component;
  size_t coefficient;

  mlk_polyvec_frombytes(secret, secret_key);
  for (component = 0; component < MLKEM_K; ++component)
  {
    for (coefficient = 0; coefficient < MLKEM_N; ++coefficient)
    {
      const int16_t value = secret[component].coeffs[coefficient];
      if (value < 0 || value >= MLKEM_Q)
      {
        bridge_zeroize(&secret, sizeof(secret));
        return -1;
      }
      output[component * MLKEM_N + coefficient] = (uint16_t)value;
    }
  }
  bridge_zeroize(&secret, sizeof(secret));
  return 0;
}

static void load_s_hat(mlk_polyvec output, const uint16_t input[512])
{
  size_t component;
  size_t coefficient;
  for (component = 0; component < MLKEM_K; ++component)
  {
    for (coefficient = 0; coefficient < MLKEM_N; ++coefficient)
    {
      output[component].coeffs[coefficient] =
          (int16_t)input[component * MLKEM_N + coefficient];
    }
  }
}

int rmtls_mlkem512_public_u_hat(uint16_t output[512],
                                const uint8_t ciphertext[768])
{
  mlk_polyvec public_u;
  size_t component;
  size_t coefficient;

  mlk_polyvec_decompress_du(public_u, ciphertext);
  mlk_polyvec_ntt(public_u);
  for (component = 0; component < MLKEM_K; ++component)
  {
    for (coefficient = 0; coefficient < MLKEM_N; ++coefficient)
    {
      output[component * MLKEM_N + coefficient] =
          canonical_coefficient(public_u[component].coeffs[coefficient]);
    }
  }
  bridge_zeroize(&public_u, sizeof(public_u));
  return 0;
}

int rmtls_mlkem512_assistant_inner(uint16_t output[256],
                                   const uint16_t share[512],
                                   const uint8_t ciphertext[768])
{
  mlk_polyvec share_vector;
  mlk_polyvec public_u;
  mlk_polyvec_mulcache public_u_cache;
  mlk_poly product;
  size_t coefficient;

  load_s_hat(share_vector, share);
  mlk_polyvec_decompress_du(public_u, ciphertext);
  mlk_polyvec_ntt(public_u);
  mlk_polyvec_mulcache_compute(public_u_cache, public_u);
  mlk_polyvec_basemul_acc_montgomery_cached(
      &product, share_vector, public_u, public_u_cache);
  for (coefficient = 0; coefficient < MLKEM_N; ++coefficient)
  {
    output[coefficient] =
        canonical_coefficient(product.coeffs[coefficient]);
  }

  bridge_zeroize(&share_vector, sizeof(share_vector));
  bridge_zeroize(&public_u, sizeof(public_u));
  bridge_zeroize(&public_u_cache, sizeof(public_u_cache));
  bridge_zeroize(&product, sizeof(product));
  return 0;
}

int rmtls_mlkem512_dec_msg_from_combined(uint8_t message[32],
                                         const uint16_t combined[256],
                                         const uint8_t ciphertext[768])
{
  mlk_poly product;
  mlk_poly v;
  size_t coefficient;

  for (coefficient = 0; coefficient < MLKEM_N; ++coefficient)
  {
    product.coeffs[coefficient] = (int16_t)combined[coefficient];
  }
  mlk_poly_invntt_tomont(&product);
  mlk_poly_decompress_dv(
      &v, ciphertext + MLKEM_POLYVECCOMPRESSEDBYTES_DU);
  mlk_poly_sub(&v, &product);
  mlk_poly_reduce(&v);
  mlk_poly_tomsg(message, &v);

  bridge_zeroize(&product, sizeof(product));
  bridge_zeroize(&v, sizeof(v));
  return 0;
}

int rmtls_mlkem512_dec_msg(uint8_t message[32],
                           const uint16_t s_hat[512],
                           const uint8_t ciphertext[768])
{
  uint16_t combined[256];
  const int contribution_status =
      rmtls_mlkem512_assistant_inner(combined, s_hat, ciphertext);
  int result;
  if (contribution_status != 0)
  {
    bridge_zeroize(combined, sizeof(combined));
    return contribution_status;
  }
  result =
      rmtls_mlkem512_dec_msg_from_combined(message, combined, ciphertext);
  bridge_zeroize(combined, sizeof(combined));
  return result;
}

int rmtls_mlkem512_fo_validate(uint8_t shared_secret[32],
                               const uint8_t message[32],
                               const uint8_t ciphertext[768],
                               const uint8_t public_key[800],
                               const uint8_t fallback_secret[32])
{
  uint8_t hash_input[64];
  uint8_t key_and_coins[64];
  uint8_t reconstructed[768];
  uint8_t rejection_input[800];
  uint8_t failure = 0;
  size_t index;

  memcpy(hash_input, message, 32);
  mlk_hash_h(hash_input + 32, public_key, 800);
  mlk_hash_g(key_and_coins, hash_input, sizeof(hash_input));
  mlk_indcpa_enc(
      reconstructed, message, public_key, key_and_coins + 32);
  for (index = 0; index < sizeof(reconstructed); ++index)
  {
    failure |= (uint8_t)(reconstructed[index] ^ ciphertext[index]);
  }

  memcpy(rejection_input, fallback_secret, 32);
  memcpy(rejection_input + 32, ciphertext, 768);
  mlk_hash_j(shared_secret, rejection_input, sizeof(rejection_input));
  {
    const uint8_t success =
        (uint8_t)((((uint16_t)failure - 1u) >> 8) & 1u);
    const uint8_t mask = (uint8_t)(0u - success);
    for (index = 0; index < 32; ++index)
    {
      shared_secret[index] =
          (uint8_t)((shared_secret[index] & (uint8_t)~mask) |
                    (key_and_coins[index] & mask));
    }
  }

  bridge_zeroize(hash_input, sizeof(hash_input));
  bridge_zeroize(key_and_coins, sizeof(key_and_coins));
  bridge_zeroize(reconstructed, sizeof(reconstructed));
  bridge_zeroize(rejection_input, sizeof(rejection_input));
  bridge_zeroize(&failure, sizeof(failure));
  return 0;
}

void rmtls_sha3_256(uint8_t output[32],
                    const uint8_t* input,
                    size_t input_length)
{
  mlk_sha3_256(output, input, input_length);
}

void rmtls_shake256(uint8_t* output,
                    size_t output_length,
                    const uint8_t* input,
                    size_t input_length)
{
  mlk_shake256(output, output_length, input, input_length);
}
