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

    if ( ( 128UL != keybits ) && ( 256UL != keybits ) ) {
        /* Unsupported key size */
        return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
    
    ctx->keybits = keybits;

    CRYPTO_TypeDef *device = crypto_management_acquire();

    crypto_management_critical_enter();

    CRYPTO_KeyBufWrite(device, (uint32_t*)key, (keybits == 128) ? cryptoKey128Bits : cryptoKey256Bits);

    CRYPTO_EXECUTE_1(device, CRYPTO_CMD_INSTR_AESENC);

    CRYPTO_KeyRead(device, (uint32_t*)ctx->key, (keybits == 128) ? cryptoKey128Bits : cryptoKey256Bits);

    crypto_management_critical_exit();

    crypto_management_release(device);

    return 0;
}

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

    CRYPTO_TypeDef *device = crypto_management_acquire();

    crypto_management_critical_enter();

    switch( ctx->keybits )
    {
    case 128UL:
        CRYPTO_AES_ECB128( device,
                           output,
                           input,
                           16,
                           ctx->key,
                           mode == MBEDTLS_AES_ENCRYPT ?  true : false );
        break;
    
    case 256UL:
        CRYPTO_AES_ECB256( device,
                           output,
                           input,
                           16,
                           ctx->key,
                           mode == MBEDTLS_AES_ENCRYPT ?  true : false );
        break;
        
    default:
        ret = MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
        break;
    }

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
    
    if( ctx == NULL || input == NULL || output == NULL || iv == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    /* Input length must be a multiple of 16 bytes which is the AES block
       length. */
    if( length & 0xf ) {
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }

    CRYPTO_TypeDef *device = crypto_management_acquire();

    crypto_management_critical_enter();

    switch( ctx->keybits )
    {
    case 128UL:
        CRYPTO_AES_CBC128( device,
                           output,
                           input,
                           length,
                           ctx->key,
                           iv,
                           mode == MBEDTLS_AES_ENCRYPT ?  true : false );
        break;
    
    case 256UL:
        CRYPTO_AES_CBC256( device,
                           output,
                           input,
                           length,
                           ctx->key,
                           iv,
                           mode == MBEDTLS_AES_ENCRYPT ?  true : false );
        break;
        
    default:
        ret = MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
        break;
    }

    crypto_management_critical_exit();

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
    int ret;

    if( ctx == NULL || input == NULL || output == NULL || iv == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }
    
    if ( n || ( length & 0xf ) )
    {
        int c;

        if( mode == MBEDTLS_AES_DECRYPT )
        {
            while( length-- )
            {
                if( n == 0 ) {
                    ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
                    if ( ret != 0 ) {
                        return ret;
                    }
                }
                
                c = *input++;
                *output++ = (unsigned char)( c ^ iv[n] );
                iv[n] = (unsigned char) c;
                
                n = ( n + 1 ) & 0x0F;
            }
        }
        else
        {
            while( length-- )
            {
                if( n == 0 ) {
                    ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
                    if ( ret != 0 ) {
                        return ret;
                    }
                }
                
                iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );
                
                n = ( n + 1 ) & 0x0F;
            }
        }

        if (iv_off)
        {
            *iv_off = n;
        }
        return( 0 );
    }
    else
    {
        CRYPTO_TypeDef *device = crypto_management_acquire();
        crypto_management_critical_enter();

        switch( ctx->keybits )
        {
        case 128:
            CRYPTO_AES_CFB128( device,
                               output,
                               input,
                               length,
                               (uint8_t*)ctx->key,
                               iv,
                               mode == MBEDTLS_AES_ENCRYPT ?
                               true : false );
        break;
    
        case 256:
            CRYPTO_AES_CFB256( device,
                               output,
                               input,
                               length,
                               (uint8_t*)ctx->key,
                               iv,
                               mode == MBEDTLS_AES_ENCRYPT ?
                               true : false );
            break;
        
        default:
            ret = MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
            break;
        }

        crypto_management_critical_exit();
        crypto_management_release(device);
         
        return( ret );
    }
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

 cleanup:
    
    return( ret );
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
    int ret;

    if( ctx == NULL || input == NULL || output == NULL || nonce_counter == NULL || stream_block == NULL ) {
        return ( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );
    }
    
    if ( n || ( length & 0xf ) )
    {
        int c, i;
    
        while( length-- )
        {
            if( n == 0 )
            {
                ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block );
                if ( ret != 0 ) {
                    return ret;
                }

                for( i = 16; i > 0; i-- )
                    if( ++nonce_counter[i - 1] != 0 )
                        break;
            }
            c = *input++;
            *output++ = (unsigned char)( c ^ stream_block[n] );

            n = ( n + 1 ) & 0x0F;
        }

        if (nc_off)
        {
            *nc_off = n;
        }
        return( 0 );
    }
    else
    {
        CRYPTO_TypeDef *device = crypto_management_acquire();
        crypto_management_critical_enter();

        switch( ctx->keybits )
        {
        case 128:
            CRYPTO_AES_CTR128( device,
                               output,
                               input,
                               length,
                               (uint8_t*)ctx->key,
                               nonce_counter,
                               NULL );
        break;
    
        case 256:
            CRYPTO_AES_CTR256( device,
                               output,
                               input,
                               length,
                               (uint8_t*)ctx->key,
                               nonce_counter,
                               NULL );
            break;
        
        default:
            ret = MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
            break;
        }

        crypto_management_critical_exit();
        crypto_management_release(device);
        
        return ret;
    }
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#endif /* CRYPTO_PRESENT */

#endif /* MBEDTLS_AES_ALT */

#endif /* MBEDTLS_AES_C */
