/*
 *  BLE-specific cipher implementations optimized for Silicon Labs devices
 *  with a CRYPTO peripheral.
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

#include "crypto_ble.h"
#include "em_device.h"

#if defined(CRYPTO_PRESENT)

#include "crypto_management.h"
#include "em_crypto.h"
#include <string.h>

/***************************************************************************//**
 * @brief
 *   Write a 128 bit value (optionally unaligned) into a crypto register.
 *
 * @note
 *   This function provide a low-level api for writing to the multi-word
 *   registers in the crypto peripheral. Applications should prefer to use
 *   @ref CRYPTO_DataWrite, @ref CRYPTO_DDataWrite or @ref CRYPTO_QDataWrite
 *   for writing to the DATA, DDATA and QDATA registers.
 *
 * @param[in]  reg
 *   Pointer to the crypto register.
 *
 * @param[in]  val
 *   This is a pointer to 4 32 bit integers that contains the 128 bit value
 *   which will be written to the crypto register.
 ******************************************************************************/
__STATIC_INLINE void CRYPTO_DataWriteUnaligned(volatile uint32_t * reg,
                                               const uint8_t * val)
{
  /* Check data is 32bit aligned, if not move to temporary buffer before
     writing.*/
  if ((uint32_t)val & 0x3)
  {
    uint32_t temp[4];
    memcpy(temp, val, 16);
    CRYPTO_DataWrite(reg, temp);
  }
  else
  {
    CRYPTO_DataWrite(reg, (uint32_t*)val);
  }
}

/***************************************************************************//**
 * @brief
 *   Read a 128 bit value from a crypto register into optionally unaligned
 *   buffer.
 *
 * @note
 *   This function provide a low-level api for reading one of the multi-word
 *   registers in the crypto peripheral. Applications should prefer to use
 *   @ref CRYPTO_DataRead, @ref CRYPTO_DDataRead or @ref CRYPTO_QDataRead
 *   for reading the value of the DATA, DDATA and QDATA registers.
 *
 * @param[in]  reg
 *   Pointer to the crypto register.
 *
 * @param[out]  val
 *   This is a pointer to an array that is capable of holding 4 32 bit integers
 *   that will be filled with the 128 bit value from the crypto register.
 ******************************************************************************/
__STATIC_INLINE void CRYPTO_DataReadUnaligned(volatile uint32_t * reg,
                                              uint8_t * val)
{
  /* Check data is 32bit aligned, if not, read into temporary buffer and
     then move to user buffer. */
  if ((uint32_t)val & 0x3)
  {
    uint32_t temp[4];
    CRYPTO_DataRead(reg, temp);
    memcpy(val, temp, 16);
  }
  else
  {
    CRYPTO_DataRead(reg, (uint32_t*)val);
  }
}

/*
 * CCM buffer encryption optimized for BLE
 */
int mbedtls_ccm_encrypt_and_tag_ble( unsigned char       *data,
                                     size_t               length,
                                     const unsigned char *key,
                                     const unsigned char *iv,
                                     unsigned char        header,
                                     unsigned char       *tag )
{
    /* Local variables used to optimize load/store sequences from memory to
     crypto. We want to load all 4 32bit data words to local register
     variables in the first sequence, then store them all in the second
     sequence.*/
    register uint32_t iv0;
    register uint32_t iv1;
    register uint32_t iv2;
    register uint32_t iv3;
    CRYPTO_TypeDef   *device    = crypto_management_acquire_preemption();

    /* Setup CRYPTO for AES-128 mode (256 not supported) */
    device->CTRL      = CRYPTO_CTRL_AES_AES128;
    device->WAC       = 0UL;
    
    if (key)
    {
        CRYPTO_KeyBuf128Write(device, (uint32_t *)key);
    }

    /* Calculate Counter IV for encryption. */
    iv0 = 0x01 | (*(uint32_t *)(&iv[0]) << 8);
    iv1 = *(uint32_t *)(&iv[3]);
    iv2 = *(uint32_t *)(&iv[7]);
    iv3 = *(uint16_t *)(&iv[11]);

    /* Store Counter IV in crypto->DATA1 */
    device->DATA1 = iv0;
    device->DATA1 = iv1;
    device->DATA1 = iv2;
    device->DATA1 = iv3;

    /* Calculate CBC IV for authentication. */
    iv0 |= 0x49;
    iv3 |= __REV(length);

    /* Store CBC IV in device->DATA0 */
    device->DATA0 = iv0;
    device->DATA0 = iv1;
    device->DATA0 = iv2;
    device->DATA0 = iv3;

    /* Store header in device->DATA3 */
    device->DATA3 = 0x0100 | (header << 16);
    device->DATA3 = 0;
    device->DATA3 = 0;
    device->DATA3 = 0;

    device->SEQCTRL  = length;
    device->SEQCTRLB = 0;
  
    /* The following code is tested to run faster than using instruction
     sequences. */
    device->CMD = CRYPTO_CMD_INSTR_AESENC;
    device->CMD = CRYPTO_CMD_INSTR_DATA3TODATA0XOR;
    device->CMD = CRYPTO_CMD_INSTR_AESENC;
    device->CMD = CRYPTO_CMD_INSTR_DATA0TODATA3;

    CRYPTO_EXECUTE_16(device,
                      CRYPTO_CMD_INSTR_EXECIFA,
                      
                      // CRYPTO_CMD_INSTR_BUFTODATA0,
                      CRYPTO_CMD_INSTR_DMA0TODATA,
                      CRYPTO_CMD_INSTR_DATA0TODATA2, // save DMA value
                      
                      CRYPTO_CMD_INSTR_DATA3TODATA0XOR,
                      CRYPTO_CMD_INSTR_AESENC,
                      CRYPTO_CMD_INSTR_DATA0TODATA3,
                      CRYPTO_CMD_INSTR_DATA1INC,
                      CRYPTO_CMD_INSTR_DATA1TODATA0,
                      CRYPTO_CMD_INSTR_AESENC,
                      //CRYPTO_CMD_INSTR_DATA0TOBUFXOR,
                      CRYPTO_CMD_INSTR_DATA2TODATA0XOR,//data0 = data0 xor dma
                      CRYPTO_CMD_INSTR_DATATODMA0,
                      
                      CRYPTO_CMD_INSTR_EXECIFLAST,
                      CRYPTO_CMD_INSTR_DATA1INCCLR,
                      CRYPTO_CMD_INSTR_DATA1TODATA0,
                      CRYPTO_CMD_INSTR_AESENC,
                      CRYPTO_CMD_INSTR_DATA3TODATA0XOR
                      );
    
    uint32_t tempBuf[4];

    while (length)
    {
        if (length < 16) {
            /* Use temporary buffer for zero padding */
            memset( tempBuf, 0, 16 );
            memcpy( tempBuf, data, length );
            CRYPTO_DataWrite( &device->DATA0, tempBuf );
            CRYPTO_DataRead( &device->DATA0, tempBuf );
            memcpy( data, tempBuf, length );
            length = 0;
        } else {
            CRYPTO_DataWriteUnaligned( &device->DATA0, data );
            CRYPTO_DataReadUnaligned( &device->DATA0, data );
            length  -= 16;
            data    += 16;
        }
    }

    /* Read authentication tag from DATA0 register. */
    CRYPTO_DataRead( &device->DATA0, tempBuf );
    *((uint32_t*)tag) = tempBuf[0];

    crypto_management_release_preemption( device );

    return 0;
}

/*
 * CCM buffer authenticated decryption optimized for BLE
 */
int mbedtls_ccm_auth_decrypt_ble( unsigned char       *data,
                                  size_t               length,
                                  const unsigned char *key,
                                  const unsigned char *iv,
                                  unsigned char        header,
                                  unsigned char       *tag )
{
    /* Local variables used to optimize load/store sequences from memory to
     crypto. We want to load all 4 32bit data words to local register
     variables in the first sequence, then store them all in the second
     sequence.*/
    register uint32_t iv0;
    register uint32_t iv1;
    register uint32_t iv2;
    register uint32_t iv3;
    CRYPTO_TypeDef   *device    = crypto_management_acquire_preemption();

    /* Setup CRYPTO for AES-128 mode (256 not supported) */
    device->CTRL      = CRYPTO_CTRL_AES_AES128;
    device->WAC       = 0UL;
    
    if (key)
    {
        CRYPTO_KeyBuf128Write(device, (uint32_t *)key);
    }

    /* Calculate Counter IV for encryption. */
    iv0 = 0x01 | (*(uint32_t *)(&iv[0]) << 8);
    iv1 = *(uint32_t *)(&iv[3]);
    iv2 = *(uint32_t *)(&iv[7]);
    iv3 = *(uint16_t *)(&iv[11]);

    /* Store Counter IV in crypto->DATA1 */
    device->DATA1 = iv0;
    device->DATA1 = iv1;
    device->DATA1 = iv2;
    device->DATA1 = iv3;

    /* Calculate CBC IV for authentication. */
    iv0 |= 0x49;
    iv3 |= __REV(length);

    /* Store CBC IV in device->DATA0 */
    device->DATA0 = iv0;
    device->DATA0 = iv1;
    device->DATA0 = iv2;
    device->DATA0 = iv3;

    /* Store header in device->DATA3 */
    device->DATA3 = 0x0100 | (header << 16);
    device->DATA3 = 0;
    device->DATA3 = 0;
    device->DATA3 = 0;

    device->SEQCTRL  = length;
    device->SEQCTRLB = 0;
  
    /* The following code is tested to run faster than using instruction
     sequences. */
    device->CMD = CRYPTO_CMD_INSTR_AESENC;
    device->CMD = CRYPTO_CMD_INSTR_DATA3TODATA0XOR;
    device->CMD = CRYPTO_CMD_INSTR_AESENC;
    device->CMD = CRYPTO_CMD_INSTR_DATA0TODATA3;

    CRYPTO_EXECUTE_18(device,
                      CRYPTO_CMD_INSTR_EXECIFA,
                      /* AESDRV_CTR_PREPARE_PROC */
                      CRYPTO_CMD_INSTR_DATA1INC,
                      CRYPTO_CMD_INSTR_DATA1TODATA0,
                      CRYPTO_CMD_INSTR_AESENC,
                      
                      // CRYPTO_CMD_INSTR_BUFTODATA0XOR,
                      // CRYPTO_CMD_INSTR_DATA0TOBUF,
                      CRYPTO_CMD_INSTR_DATA0TODATA2,
                      CRYPTO_CMD_INSTR_DMA0TODATA,
                      CRYPTO_CMD_INSTR_DATA2TODATA0XORLEN,
                      CRYPTO_CMD_INSTR_DATATODMA0,
                      
                      CRYPTO_CMD_INSTR_DATA0TODATA2,
                      CRYPTO_CMD_INSTR_DATA3TODATA0,
                      CRYPTO_CMD_INSTR_DATA2TODATA0XORLEN,
                      
                      CRYPTO_CMD_INSTR_AESENC,
                      CRYPTO_CMD_INSTR_DATA0TODATA3,
                      
                      CRYPTO_CMD_INSTR_EXECIFLAST,
                      CRYPTO_CMD_INSTR_DATA1INCCLR,
                      CRYPTO_CMD_INSTR_DATA1TODATA0,
                      CRYPTO_CMD_INSTR_AESENC,
                      CRYPTO_CMD_INSTR_DATA3TODATA0XOR
                      );
    
    uint32_t tempBuf[4];

    while (length)
    {
        if (length < 16) {
            /* Use temporary buffer for zero padding */
            memset( tempBuf, 0, 16 );
            memcpy( tempBuf, data, length );
            CRYPTO_DataWrite( &device->DATA0, tempBuf );
            CRYPTO_DataRead( &device->DATA0, tempBuf );
            memcpy( data, tempBuf, length );
            length = 0;
        } else {
            CRYPTO_DataWriteUnaligned( &device->DATA0, data );
            CRYPTO_DataReadUnaligned( &device->DATA0, data );
            length  -= 16;
            data    += 16;
        }
    }

    /* Read authentication tag from DATA0 register. */
    CRYPTO_DataRead( &device->DATA0, tempBuf );
    crypto_management_release_preemption( device );

    if ( *tag == tempBuf[0] ) {
        return 0;
    } else {
        return MBEDTLS_ERR_CCM_AUTH_FAILED;
    }
}

/*
 * Process a table of BLE RPA device keys and look for a
 * match against the supplied hash
 */
int mbedtls_process_ble_rpa(  unsigned char         **keytable,
                              size_t                length,
                              const unsigned char   prand[3],
                              const unsigned char   hash[3],
                              size_t                *match )
{
    CRYPTO_TypeDef *device = crypto_management_acquire_preemption();
    bool done = false;
    size_t index;
    /* Set up CRYPTO to do AES, and load prand */
    device->CTRL     = CRYPTO_CTRL_AES_AES128;
    device->SEQCTRL  = 0UL;
    device->SEQCTRLB = 0UL;
    device->WAC      = 0UL;

    unsigned char data_register[16] = {0};
    data_register[13] = prand[0];
    data_register[14] = prand[1];
    data_register[15] = prand[2];
    CRYPTO_DataWrite(&device->DATA1, (uint32_t*)data_register);


    CRYPTO_SEQ_LOAD_2( device,
                       CRYPTO_CMD_INSTR_DATA1TODATA0,
                       CRYPTO_CMD_INSTR_AESENC);

    /* For each key, execute AES encrypt operation and compare w hash */
    for ( index = 0; (index < length) && (!done); index++ ) {
        CRYPTO_DataWrite(&device->KEY, (uint32_t*)keytable[index]);
        CRYPTO_InstructionSequenceExecute(device);
        /* To save cycles, we can do the comparison here while AES executes */
        if ( index > 0 ) {
            if ( (data_register[13] == hash[0])
                 && (data_register[14] == hash[1])
                 && (data_register[15] == hash[2]) ) {
                *match = index - 1;
                done = true;
                while (!CRYPTO_InstructionSequenceDone(device));
                break;
            }
        }
        CRYPTO_DataRead(&device->DATA0, (uint32_t*)data_register);
    }

    if ( (!done) && (index > 0) ) {
        if ( (data_register[13] == hash[0])
             && (data_register[14] == hash[1])
             && (data_register[15] == hash[2]) ) {
            *match = index - 1;
            done = true;
        }
    }

    if ( done ) {
        crypto_management_release_preemption(device);
        return 0;
    } else {
        crypto_management_release_preemption(device);
        return -1;
    }    
}

#endif /* CRYPTO_PRESENT */