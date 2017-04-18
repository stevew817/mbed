/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright (C) 2017, Silicon Labs, http://www.silabs.com
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * This file includes alternative plugin implementations of various
 * functions in aes.c using the CRYPTO hardware accelerator incorporated
 * in MCU devices from Silicon Laboratories.
 */

/*
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

#include "mbedtls/aes.h"

#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_AES_ALT)

#include "em_device.h"

#if defined(CRYPTO_PRESENT)

#include "crypto_management.h"
#include "em_crypto.h"
#include <string.h>

/*
 * Initialize AES context
 */
void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    if( ctx == NULL ) {
        return;
    }

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}

/*
 * Clear AES context
 */
void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL ) {
        return;
    }

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}

/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits )
{
    if( ctx == NULL || key == NULL ) {
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );

    if ( ( 128UL != keybits ) && ( 256UL != keybits ) ) {
        /* Unsupported key size */
        return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    ctx->keybits = keybits;
    memcpy(ctx->key, key, keybits/8);
    
    return 0;
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits )
{
    if( ctx == NULL || key == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );

    if ( ( 128UL != keybits ) && ( 256UL != keybits ) ) {
        /* Unsupported key size */
        return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
    
    ctx->keybits = keybits;

    CRYPTO_TypeDef *device = crypto_management_acquire();
    device->WAC = 0;
    device->CTRL = 0;

    crypto_management_critical_enter();
    CRYPTO_KeyBufWrite(device, (uint32_t*)key, (keybits == 128) ? cryptoKey128Bits : cryptoKey256Bits);
    crypto_management_critical_exit();

    /* Busy-wait here to allow context-switching to occur */
    device->CMD = CRYPTO_CMD_INSTR_AESENC;
    while ((device->STATUS & CRYPTO_STATUS_INSTRRUNNING) != 0);

    crypto_management_critical_enter();
    CRYPTO_KeyRead(device, (uint32_t*)ctx->key, (keybits == 128) ? cryptoKey128Bits : cryptoKey256Bits);
    crypto_management_critical_exit();

    crypto_management_release(device);

    return 0;
}

/* TODO: underneath these, we should swap out the em_crypto-provided library
 * functions with in-place implemented functions, to get much shorter
 * critical sections */

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
    int ret = 0;

    if( ctx == NULL || input == NULL || output == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    if ( ctx->keybits != 128UL && ctx->keybits != 256UL) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    CRYPTO_TypeDef *device = crypto_management_acquire();
    device->WAC = 0;
    device->CTRL = 0;

    crypto_management_critical_enter();
    CRYPTO_KeyBufWrite(device, (uint32_t*)ctx->key, (ctx->keybits == 128UL) ? cryptoKey128Bits : cryptoKey256Bits);
    CRYPTO_DataWrite(&device->DATA0, (uint32_t *)input);
    crypto_management_critical_exit();
    
    if ( mode == MBEDTLS_AES_ENCRYPT ) {
        device->CMD = CRYPTO_CMD_INSTR_AESENC;
    } else {
        device->CMD = CRYPTO_CMD_INSTR_AESDEC;
    }
    while ((device->STATUS & CRYPTO_STATUS_INSTRRUNNING) != 0);

    crypto_management_critical_enter();
    CRYPTO_DataRead(&device->DATA0, (uint32_t *)output);
    crypto_management_critical_exit();

    crypto_management_release(device);
    
    return ret;
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)

/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = 0;
    size_t processed = 0;
    
    if( ctx == NULL || input == NULL || output == NULL || iv == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    /* Input length must be a multiple of 16 bytes which is the AES block
       length. */
    if( length & 0xf ) {
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    if ( ctx->keybits != 128UL && ctx->keybits != 256UL) {
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    CRYPTO_TypeDef *device = crypto_management_acquire();
    device->WAC = 0;
    device->CTRL = 0;

    crypto_management_critical_enter();
    CRYPTO_KeyBufWrite(device, (uint32_t*)ctx->key, (ctx->keybits == 128UL) ? cryptoKey128Bits : cryptoKey256Bits);
    if ( mode == MBEDTLS_AES_ENCRYPT ) {
        CRYPTO_DataWrite(&device->DATA0, (uint32_t *)iv);
    } else {
        CRYPTO_DataWrite(&device->DATA2, (uint32_t *)iv);
    }
    crypto_management_critical_exit();

    while ( processed < length ) {
        if ( mode == MBEDTLS_AES_ENCRYPT ) {
            crypto_management_critical_enter();
            CRYPTO_DataWrite(&device->DATA0XOR, (uint32_t *)(&input[processed]));
            device->CMD = CRYPTO_CMD_INSTR_AESENC;
            CRYPTO_DataRead(&device->DATA0, (uint32_t *)(&output[processed]));
            crypto_management_critical_exit();
        } else {
            /* Decrypt input block, XOR IV to decrypted text, set ciphertext as next IV */
            crypto_management_critical_enter();
            CRYPTO_DataWrite(&device->DATA0, (uint32_t *)(&input[processed]));
            CRYPTO_EXECUTE_4( device,
                              CRYPTO_CMD_INSTR_DATA0TODATA1,
                              CRYPTO_CMD_INSTR_AESDEC,
                              CRYPTO_CMD_INSTR_DATA2TODATA0XOR,
                              CRYPTO_CMD_INSTR_DATA1TODATA2);
            CRYPTO_DataRead(&device->DATA0, (uint32_t *)(&output[processed]));
            crypto_management_critical_exit();
        }
        processed += 16;
    }

    if ( processed >= 16 ) {
        if ( mode == MBEDTLS_AES_ENCRYPT ) {
            memcpy(iv, &output[processed-16], 16);
        } else {
            crypto_management_critical_enter();
            CRYPTO_DataRead(&device->DATA2, (uint32_t *)(iv));
            crypto_management_critical_exit();
        }
    }

    crypto_management_release(device);
    
    return ret;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * AES-CFB128 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                              int mode,
                              size_t length,
                              size_t *iv_off,
                              unsigned char iv[16],
                              const unsigned char *input,
                              unsigned char *output )
{
    size_t n = iv_off ? *iv_off : 0;
    size_t processed = 0;
    int ret = 0;

    if( ctx == NULL || input == NULL || output == NULL || iv == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }
    
    while ( processed < length ) {
        if ( n > 0 ) {
            /* start by filling up the IV */
            if( mode == MBEDTLS_AES_ENCRYPT ) {
                iv[n] = output[processed] = (unsigned char)( iv[n] ^ input[processed] );
            } else {
                int c = input[processed];
                output[processed] = (unsigned char)( c ^ iv[n] );
                iv[n] = (unsigned char) c;
            }
            n = ( n + 1 ) & 0x0F;
            processed++;
            continue;
        } else {
            /* process one ore more blocks of data */
            CRYPTO_TypeDef *device = crypto_management_acquire();
            device->WAC = 0;
            device->CTRL = 0;

            crypto_management_critical_enter();
            CRYPTO_KeyBufWrite(device, (uint32_t*)ctx->key, (ctx->keybits == 128UL) ? cryptoKey128Bits : cryptoKey256Bits);
            CRYPTO_DataWrite(&device->DATA0, (uint32_t *)iv);
            crypto_management_critical_exit();

            /* Encryption: encrypt IV, encIV xor input -> output and IV */
            /* Decryption: encrypt IV, encIV xor input -> output, input -> IV */
            size_t iterations = (length - processed) / 16;
            for (size_t i = 0; i < iterations; i++ ) {
                device->CMD = CRYPTO_CMD_INSTR_AESENC;
                while ((device->STATUS & CRYPTO_STATUS_INSTRRUNNING) != 0);

                crypto_management_critical_enter();
                if ( mode == MBEDTLS_AES_ENCRYPT ) {
                    CRYPTO_DataWrite(&device->DATA0XOR, (uint32_t *)(&input[processed]));
                    CRYPTO_DataRead(&device->DATA0, (uint32_t *)(&output[processed]));
                } else {
                    CRYPTO_DataWrite(&device->DATA1, (uint32_t *)(&input[processed]));
                    device->CMD = CRYPTO_CMD_INSTR_DATA1TODATA0XOR;
                    CRYPTO_DataRead(&device->DATA0, (uint32_t *)(&output[processed]));
                    device->CMD = CRYPTO_CMD_INSTR_DATA1TODATA0;
                }
                crypto_management_critical_exit();
                processed += 16;
            }

            crypto_management_critical_enter();
            CRYPTO_DataRead(&device->DATA0, (uint32_t *)iv);
            crypto_management_critical_exit();

            while ( length - processed > 0 ) {
                if ( n == 0 ) {
                    device->CMD = CRYPTO_CMD_INSTR_AESENC;
                    while ((device->STATUS & CRYPTO_STATUS_INSTRRUNNING) != 0);
                    crypto_management_critical_enter();
                    CRYPTO_DataRead(&device->DATA0, (uint32_t *)iv);
                    crypto_management_critical_exit();
                }
                /* Save remainder to iv */
                if( mode == MBEDTLS_AES_ENCRYPT ) {
                    iv[n] = output[processed] = (unsigned char)( iv[n] ^ input[processed] );
                } else {
                    int c = input[processed];
                    output[processed] = (unsigned char)( c ^ iv[n] );
                    iv[n] = (unsigned char) c;
                }
                n = ( n + 1 ) & 0x0F;
                processed++;
            }

            crypto_management_release(device);
        }
    }

    if ( iv_off ) {
        *iv_off = n;
    }

    return ret;
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output )
{
    unsigned char c;
    unsigned char ov[17];
    int ret = 0;

    if( ctx == NULL || input == NULL || output == NULL || iv == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    while( length-- )
    {
        memcpy( ov, iv, 16 );
        if ( (ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv ) ) != 0 ) {
            return ret;
        }

        if( mode == MBEDTLS_AES_DECRYPT )
            ov[16] = *input;

        c = *output++ = (unsigned char)( iv[0] ^ *input++ );

        if( mode == MBEDTLS_AES_ENCRYPT )
            ov[16] = c;

        memcpy( iv, ov + 1, 16 );
    }

    return ret;
}
#endif /*MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                           size_t length,
                           size_t *nc_off,
                           unsigned char nonce_counter[16],
                           unsigned char stream_block[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    size_t n = nc_off ? *nc_off : 0;
    size_t processed = 0;
    int ret;

    if( ctx == NULL || input == NULL || output == NULL || nonce_counter == NULL || stream_block == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    while ( processed < length ) {
        if ( n > 0 ) {
            /* start by filling up the IV */
            output[processed] = (unsigned char)( input[processed] ^ stream_block[n] );
            n = ( n + 1 ) & 0x0F;
            processed++;
            continue;
        } else {
            /* process one ore more blocks of data */
            CRYPTO_TypeDef *device = crypto_management_acquire();
            device->WAC = 0;
            device->CTRL = CRYPTO_CTRL_INCWIDTH_INCWIDTH4;

            crypto_management_critical_enter();
            CRYPTO_KeyBufWrite(device, (uint32_t*)ctx->key, (ctx->keybits == 128UL) ? cryptoKey128Bits : cryptoKey256Bits);
            CRYPTO_DataWrite(&device->DATA1, (uint32_t *)nonce_counter);
            crypto_management_critical_exit();

            /* strategy: encrypt nonce, encNonce xor input -> output, inc(nonce) */
            size_t iterations = (length - processed) / 16;
            for (size_t i = 0; i < iterations; i++ ) {
                device->CMD = CRYPTO_CMD_INSTR_DATA1TODATA0;
                device->CMD = CRYPTO_CMD_INSTR_AESENC;
                while ((device->STATUS & CRYPTO_STATUS_INSTRRUNNING) != 0);
                device->CMD = CRYPTO_CMD_INSTR_DATA1INC;

                crypto_management_critical_enter();
                CRYPTO_DataWrite(&device->DATA0XOR, (uint32_t *)(&input[processed]));
                CRYPTO_DataRead(&device->DATA0, (uint32_t *)(&output[processed]));
                crypto_management_critical_exit();
                processed += 16;
            }

            while ( length - processed > 0 ) {
                if ( n == 0 ) {
                    device->CMD = CRYPTO_CMD_INSTR_DATA1TODATA0;
                    device->CMD = CRYPTO_CMD_INSTR_AESENC;
                    while ((device->STATUS & CRYPTO_STATUS_INSTRRUNNING) != 0);
                    device->CMD = CRYPTO_CMD_INSTR_DATA1INC;

                    crypto_management_critical_enter();
                    CRYPTO_DataRead(&device->DATA0, (uint32_t *)stream_block);
                    crypto_management_critical_exit();
                }
                /* Save remainder to iv */
                output[processed] = (unsigned char)( input[processed] ^ stream_block[n] );
                n = ( n + 1 ) & 0x0F;
                processed++;
            }

            crypto_management_critical_enter();
            CRYPTO_DataRead(&device->DATA1, (uint32_t *)nonce_counter);
            crypto_management_critical_exit();

            crypto_management_release(device);
        }
    }

    if ( nc_off ) {
        *nc_off = n;
    }

    return ret;
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#endif /* CRYPTO_PRESENT */

#endif /* MBEDTLS_AES_ALT */

#endif /* MBEDTLS_AES_C */
