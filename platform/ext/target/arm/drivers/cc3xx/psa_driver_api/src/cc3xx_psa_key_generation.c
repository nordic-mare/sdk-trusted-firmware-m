/*
 * Copyright (c) 2021-2024, The TrustedFirmware-M Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/** @file cc3xx_psa_key_generation.c
 *
 * This file contains the implementation of the entry points associated to the
 * key generation (i.e. random generation and extraction of public keys) as
 * described by the PSA Cryptoprocessor Driver interface specification
 *
 */

#include <string.h>

#include "cc3xx_psa_key_generation.h"
#include "cc3xx_psa_random.h"
#include "cc3xx_misc.h"

#include "cc3xx_stdlib.h"
#include "cc3xx_ecdsa.h"
#include "cc3xx_ec_curve_data.h"

/* ToDo: This needs to be sorted out at TF-M level
 * To be able to include the PSA style configuration
 */
#include "mbedtls/build_info.h"

/** @defgroup psa_key_generation PSA driver entry points for key handling
 *
 *  Entry points for random key generation and key format manipulation and
 *  translation as described by the PSA Cryptoprocessor Driver interface
 *  specification
 *
 *  @{
 */
psa_status_t cc3xx_generate_key(const psa_key_attributes_t *attributes,
                                uint8_t *key_buffer, size_t key_buffer_size,
                                size_t *key_buffer_length)
{
    CC3XX_ASSERT(attributes != NULL);
    CC3XX_ASSERT(key_buffer != NULL);
    CC3XX_ASSERT(key_buffer_length != NULL);

    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_key_bits_t key_bits = psa_get_key_bits(attributes);

    /* Initialise the return value to 0 */
    *key_buffer_length = 0;
    if (PSA_KEY_TYPE_IS_KEY_PAIR(key_type)) {
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
        if (PSA_KEY_TYPE_IS_ECC(key_type)) {
            cc3xx_err_t err;
            /* Translate from PSA curve ID to CC3XX curve ID*/
            const cc3xx_ec_curve_id_t curve_id =
                cc3xx_to_curve_id(PSA_KEY_TYPE_ECC_GET_FAMILY(key_type), key_bits);

            if (CC3XX_IS_CURVE_ID_INVALID(curve_id)) {
                return PSA_ERROR_NOT_SUPPORTED;
            }

            /* Local scratch with the required alignment */
            uint32_t key_buffer_local[
                CEIL_ALLOC_SZ(PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits), sizeof(uint32_t))];
            size_t gen_key_sz;

            err = cc3xx_lowlevel_ecdsa_genkey(
                curve_id, key_buffer_local, sizeof(key_buffer_local), &gen_key_sz);

            if (err != CC3XX_ERR_SUCCESS) {
                return cc3xx_to_psa_err(err);
            }

            if (gen_key_sz > key_buffer_size) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }

            /* Copy the generated key back in the output buffer */
            assert(!(gen_key_sz % sizeof(uint32_t)));
#ifdef CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE
            cc3xx_dpa_hardened_word_copy((uint32_t *)key_buffer, key_buffer_local, gen_key_sz / sizeof(uint32_t));
#else
            memcpy(key_buffer, key_buffer_local, gen_key_sz);
#endif /* CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE */
            *key_buffer_length = gen_key_sz;

            return PSA_SUCCESS;
        }
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC */
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
        if (PSA_KEY_TYPE_IS_RSA(key_type)) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    } else if (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type)) {
        return cc3xx_internal_get_random(key_buffer, key_buffer_size, key_buffer_length);
    }

    (void)key_bits;
    return PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t cc3xx_export_public_key(const psa_key_attributes_t *attributes,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size, uint8_t *data,
                                     size_t data_size, size_t *data_length)
{
    CC3XX_ASSERT(attributes != NULL);
    CC3XX_ASSERT(key_buffer != NULL);
    CC3XX_ASSERT(data != NULL);
    CC3XX_ASSERT(data_length != NULL);

    psa_key_type_t key_type = psa_get_key_type(attributes);

    /* Initialise the return value to 0 */
    *data_length = 0;

    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(key_type)) {
        /* The key is already public and in uncompressed format, 0x04 X Y, so just
         * do a memcpy on the output buffer and set the data_length accordingly
         */
        if (key_buffer_size > data_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(data, key_buffer, key_buffer_size);
        *data_length = key_buffer_size;
        return PSA_SUCCESS;
    }

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
    if (PSA_KEY_TYPE_IS_ECC(key_type)) {
        cc3xx_err_t err;
        psa_key_bits_t key_bits = psa_get_key_bits(attributes);
        /* Translate from PSA curve ID to CC3XX curve ID*/
        const cc3xx_ec_curve_id_t curve_id =
            cc3xx_to_curve_id(PSA_KEY_TYPE_ECC_GET_FAMILY(key_type), key_bits);

        if (CC3XX_IS_CURVE_ID_INVALID(curve_id)) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        const size_t modulus_sz = cc3xx_lowlevel_ec_get_modulus_size_from_curve(curve_id);

        /* Scratch aligned to 32 bits and big enough for the worst case scenario */
        uint32_t scratch_x[modulus_sz / sizeof(uint32_t)];
        uint32_t scratch_y[modulus_sz / sizeof(uint32_t)];
        size_t pub_key_x_sz, pub_key_y_sz;
        uint32_t key_buffer_local[
            CEIL_ALLOC_SZ(PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits), sizeof(uint32_t))];

#ifdef CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE
        cc3xx_dpa_hardened_word_copy(
            key_buffer_local,
            (const uint32_t *)key_buffer,
            sizeof(key_buffer_local) / sizeof(uint32_t));
#else
        memcpy(key_buffer_local, key_buffer, sizeof(key_buffer_local));
#endif /* CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE */

        err = cc3xx_lowlevel_ecdsa_getpub(
            curve_id, key_buffer_local, key_buffer_size,
            scratch_x, sizeof(scratch_x), &pub_key_x_sz,
            scratch_y, sizeof(scratch_y), &pub_key_y_sz);

        if (err != CC3XX_ERR_SUCCESS) {
            return cc3xx_to_psa_err(err);
        }

        /* Copy the result in the correct output buffer marking it as uncompressed */
        data[0] = 0x04;
        memcpy(&data[1], scratch_x, pub_key_x_sz);
        memcpy(&data[1 + pub_key_x_sz], scratch_y, pub_key_y_sz);
        *data_length = 1 + pub_key_x_sz + pub_key_y_sz;

        return PSA_SUCCESS;

    } else
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC */
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
    if (PSA_KEY_TYPE_IS_RSA(key_type)) {

        return PSA_ERROR_NOT_SUPPORTED;

    } else
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

static size_t calculate_ecc_key_size(size_t key_data_len, bool is_keypair)
{
    /* Keypairs are generally simpler because only the private key is used */
    if (is_keypair) {
        /* 521 bit curves are a special case since they are not a multiple of 8 */
        if (key_data_len == PSA_BITS_TO_BYTES(521)) {
            return 521;
        }

        return PSA_BYTES_TO_BITS(key_data_len);

    }

    /* For the SECP_R1, SECP_R2, SECP_K1 the public key has the structure
     * 04 | X | Y and the bit size of the curve is equivalent to the X/Y length.
     */
    if (key_data_len == (1 + 2 * PSA_BITS_TO_BYTES(521))) {
        return 521;
    }

    return PSA_BYTES_TO_BITS(key_data_len - 1) / 2;
}

static size_t calculate_key_size(psa_key_type_t key_type, size_t key_buff_len)
{
    /* For unstructured keys we can only rely on the buffer size to calculate the key size */
    if (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type)) {
        return PSA_BYTES_TO_BITS(key_buff_len);
    }

    if (PSA_KEY_TYPE_IS_ECC(key_type)) {
        return calculate_ecc_key_size(key_buff_len, PSA_KEY_TYPE_IS_KEY_PAIR(key_type));
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

static psa_status_t validate_ecc_key_size(psa_ecc_family_t curve, size_t bits)
{
    switch (curve) {
    case PSA_ECC_FAMILY_SECP_R1:
        if (bits != 160 && bits != 192 && bits != 224 &&
            bits != 256 && bits != 384 && bits != 521) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        return PSA_SUCCESS;
    case PSA_ECC_FAMILY_SECP_K1:
        if (bits != 160 && bits != 192 && bits != 224 && bits != 256) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        return PSA_SUCCESS;
    case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
        if (bits != 256) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        return PSA_SUCCESS;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

static psa_status_t validate_key_size(psa_key_type_t type, size_t bits)
{
    if (PSA_KEY_TYPE_IS_ECC(type)) {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY(type);
        return validate_ecc_key_size(curve, bits);
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t cc3xx_import_key(const psa_key_attributes_t *attributes,
                              const uint8_t *data, size_t data_length,
                              uint8_t *key_buffer, size_t key_buffer_size,
                              size_t *key_buffer_length, size_t *key_bits)
{
    CC3XX_ASSERT(attributes != NULL);
    CC3XX_ASSERT(data != NULL);
    CC3XX_ASSERT(key_buffer != NULL);
    CC3XX_ASSERT(key_buffer_length != NULL);
    CC3XX_ASSERT(key_bits != NULL);

    if (data_length > key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t err = PSA_ERROR_CORRUPTION_DETECTED;
    size_t attr_bits = psa_get_key_bits(attributes);
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);

    /* If the attr_bits are not set we need to calculate them. */
    if (attr_bits == 0) {
        attr_bits = calculate_key_size(key_type, data_length);
    } else {
        /* There is no need to validate the key size if we just calculated it. */
        err = validate_key_size(key_type, attr_bits);
        if (err != PSA_SUCCESS) {
            return err;
        }
    }

    /* TODO: Implement proper curve validation. */

    memcpy(key_buffer, data, data_length);
    *key_bits = attr_bits;
    *key_buffer_length = data_length;

    return PSA_SUCCESS;
}
/** @} */ // end of psa_key_generation
