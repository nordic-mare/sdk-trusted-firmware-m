/*
 * Copyright (c) 2019-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef CRYPTO_ACCELERATOR_CONF_H
#define CRYPTO_ACCELERATOR_CONF_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************************************************/
/* Require built-in implementations based on PSA requirements */
/****************************************************************/

#define PSA_WANT_KEY_TYPE_AES                   1

/* The CC312 does not support CFB mode */
#ifdef PSA_WANT_ALG_CFB
#undef PSA_WANT_ALG_CFB
#endif /* PSA_WANT_ALG_CFB */

#ifdef LEGACY_DRIVER_API_ENABLED

#ifdef PSA_WANT_KEY_TYPE_AES
#define MBEDTLS_AES_ALT
#define MBEDTLS_AES_SETKEY_ENC_ALT
#define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_AES_ENCRYPT_ALT
#define MBEDTLS_AES_DECRYPT_ALT
#endif /* PSA_WANT_KEY_TYPE_AES */

#ifdef PSA_WANT_KEY_TYPE_ARIA
#define MBEDTLS_ARIA_ALT
#endif /* PSA_WANT_KEY_TYPE_ARIA */

#ifdef PSA_WANT_ALG_CCM
#define MBEDTLS_CCM_ALT
#endif /* PSA_WANT_ALG_CCM */

#ifdef PSA_WANT_KEY_TYPE_CHACHA20
#define MBEDTLS_CHACHA20_ALT
#ifdef PSA_WANT_ALG_CHACHA20_POLY1305
#define MBEDTLS_CHACHAPOLY_ALT
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 */
#endif /* PSA_WANT_KEY_TYPE_CHACHA20 */

#ifdef PSA_WANT_ALG_CMAC
#define MBEDTLS_CMAC_ALT
#endif /* PSA_WANT_ALG_CMAC */

#ifdef PSA_WANT_ALG_ECDH
#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#endif /* PSA_WANT_ALG_ECDH */

#ifdef PSA_WANT_ALG_ECDSA
#define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_ECDSA_SIGN_ALT

#ifndef CRYPTO_HW_ACCELERATOR_OTP_PROVISIONING
#define MBEDTLS_ECDSA_GENKEY_ALT
#endif
#endif /* PSA_WANT_ALG_ECDSA */

#ifdef PSA_WANT_ALG_GCM
#define MBEDTLS_GCM_ALT
#endif /* PSA_WANT_ALG_GCM */

#ifdef PSA_WANT_ALG_SHA_1
#define MBEDTLS_SHA1_ALT
#define MBEDTLS_SHA1_PROCESS_ALT
#endif /* PSA_WANT_ALG_SHA_1 */

#ifdef PSA_WANT_ALG_SHA_256
#define MBEDTLS_SHA256_ALT
#define MBEDTLS_SHA256_PROCESS_ALT
#else
#endif /* PSA_WANT_ALG_SHA_256 */

#else /* LEGACY_DRIVER_API_ENABLED */

#ifdef PSA_WANT_KEY_TYPE_AES
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_AES
#endif

#ifdef PSA_WANT_KEY_TYPE_CHACHA20
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20
#endif

#ifdef PSA_WANT_KEY_TYPE_ECC_KEY_PAIR
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR
#endif

#ifdef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR
#endif

#ifdef PSA_WANT_ALG_ECDH
#define MBEDTLS_PSA_ACCEL_ALG_ECDH
#endif

#ifdef PSA_WANT_ALG_ECDSA
#define MBEDTLS_PSA_ACCEL_ALG_ECDSA
#endif

#ifdef PSA_WANT_ALG_DETERMINISTIC_ECDSA
#define MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C
#endif

#ifdef PSA_WANT_ALG_CBC_NO_PADDING
#define MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING
#endif

#ifdef PSA_WANT_ALG_CBC_PKCS7
#define MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7
#endif

#ifdef PSA_WANT_ALG_ECB_NO_PADDING
#define MBEDTLS_PSA_ACCEL_ALG_ECB_NO_PADDING
#endif

#ifdef PSA_WANT_ALG_CTR
#define MBEDTLS_PSA_ACCEL_ALG_CTR
#endif

#ifdef PSA_WANT_ALG_OFB
#define MBEDTLS_PSA_ACCEL_ALG_OFB
#endif

#ifdef PSA_WANT_ALG_CCM
#define MBEDTLS_PSA_ACCEL_ALG_CCM
#endif

#ifdef PSA_WANT_ALG_GCM
#define MBEDTLS_PSA_ACCEL_ALG_GCM
#define MBEDTLS_GCM_C
#endif

#ifdef PSA_WANT_ALG_CMAC
#define MBEDTLS_PSA_ACCEL_ALG_CMAC
#endif

#ifdef PSA_WANT_ALG_HMAC
#define MBEDTLS_PSA_ACCEL_ALG_HMAC
#endif

#ifdef PSA_WANT_ALG_CHACHA20_POLY1305
#define MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305
#endif

#ifdef PSA_WANT_ALG_SHA_1
#define MBEDTLS_PSA_ACCEL_ALG_SHA_1
#endif

#ifdef PSA_WANT_ALG_SHA_224
#define MBEDTLS_PSA_ACCEL_ALG_SHA_224
#endif

#ifdef PSA_WANT_ALG_SHA_256
#define MBEDTLS_PSA_ACCEL_ALG_SHA_256
#define MBEDTLS_SHA256_C
#endif

#ifdef PSA_WANT_ALG_RSA_OAEP
#define MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP
#define MBEDTLS_PKCS1_V21
#endif

#ifdef PSA_WANT_ALG_RSA_PKCS1V15_CRYPT
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT
#define MBEDTLS_PKCS1_V15
#endif

#ifdef PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN
#define MBEDTLS_PKCS1_V15
#endif

#ifdef PSA_WANT_ALG_RSA_PSS
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PSS
#define MBEDTLS_PKCS1_V21
#endif

#endif /* LEGACY_DRIVER_API_ENABLED */

#if defined(PSA_WANT_ALG_RSA_OAEP)           ||     \
    defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT) ||     \
    defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)  ||     \
    defined(PSA_WANT_ALG_RSA_PSS)            ||     \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)  ||     \
    defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
#ifdef LEGACY_DRIVER_API_ENABLED
#define MBEDTLS_RSA_ALT
#define MBEDTLS_PK_RSA_ALT_SUPPORT
#endif /* LEGACY_DRIVER_API_ENABLED */
#define MBEDTLS_GENPRIME
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CRYPTO_ACCELERATOR_CONF_H */