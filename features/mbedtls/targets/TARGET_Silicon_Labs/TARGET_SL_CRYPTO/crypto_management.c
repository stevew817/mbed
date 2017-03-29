/*
 *  Silicon Labs CRYPTO device management interface.
 *
 *  Copyright (C) 2016, Silicon Labs, http://www.silabs.com
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

#include "crypto_management.h"

#include "em_cmu.h"

#if defined( MBEDTLS_THREADING_C )
#include "mbedtls/threading.h"
static mbedtls_threading_mutex_t crypto_locks[CRYPTO_COUNT];
static bool crypto_locks_initialized = false;
#endif

#if defined( MBEDTLS_CRYPTO_DEVICE_PREEMPTION )
/** Preemptable context of CRYPTO hardware module. */
typedef struct
{
    uint32_t CTRL;          /*!< Control Register  */
    uint32_t WAC;           /*!< Wide Arithmetic Configuration  */
    uint32_t SEQCTRL;       /*!< Sequence Control  */
    uint32_t SEQCTRLB;      /*!< Sequence Control B  */
    uint32_t IEN;           /*!< Interrupt Enable Register  */
    uint32_t SEQ[5];        /*!< Instruction Sequence registers */
    CRYPTO_Data260_TypeDef DDATA[5]; /*!< DDATA registers. Covers all data
                                        registers
                                        of CRYPTO, including DATA(128 bit),
                                        DDATA (256bit/260bit),
                                        QDATA (512bit) registers. */
} crypto_context_t;
static bool crypto_was_preempted[CRYPTO_COUNT] = {false};
#endif

typedef enum
{
#if defined( CRYPTO0 )
  CRYPTO0_ID,
#elif defined( CRYPTO )
  CRYPTO_ID,
#endif
#if defined( CRYPTO1 )
  CRYPTO1_ID,
#endif
} crypto_instance_number_t;

typedef struct {
    CRYPTO_TypeDef *device;
    CMU_Clock_TypeDef clock;
} crypto_device_t;

static const crypto_device_t crypto_devices[CRYPTO_COUNT] =
{
#if defined( CRYPTO0 )
  {
    CRYPTO0,
    cmuClock_CRYPTO0
  },
#elif defined( CRYPTO )
  {
    CRYPTO,
    cmuClock_CRYPTO
  },
#endif
#if defined( CRYPTO1 )
  {
    CRYPTO1,
    cmuClock_CRYPTO1
  },
#endif
};

static inline int crypto_management_index_by_device( CRYPTO_TypeDef *device )
{
#if defined( CRYPTO0 )
  if ( device == CRYPTO0 ) return (int)CRYPTO0_ID;
#elif defined( CRYPTO )
  if ( device == CRYPTO ) return (int)CRYPTO_ID;
#endif
#if defined( CRYPTO1 )
  if ( device == CRYPTO1 ) return (int)CRYPTO1_ID;
#endif
  return 0;
}

/* Get ownership of an available crypto device */
CRYPTO_TypeDef *crypto_management_acquire( void )
{
#if defined( MBEDTLS_THREADING_C )
    if ( !crypto_locks_initialized ) {
      for ( int i = 0; i < CRYPTO_COUNT; i++ ) {
        mbedtls_mutex_init(&crypto_locks[i]);
      }
    }
#endif
    CRYPTO_TypeDef *device = NULL;

    /* Acquire device ownership mutex here */
    crypto_management_critical_enter();
#if defined( MBEDTLS_THREADING_C )
    for ( int i = 0; i < CRYPTO_COUNT; i++ ) {
        if ( 0 == mbedtls_mutex_trylock(&crypto_locks[i]) ) {
            /* Locked a device! */
            CMU_ClockEnable(crypto_devices[i].clock, true);
            device = crypto_devices[i].device;
        }
    }
    /* If no device immediately available, pend on the first one */
    if ( device == NULL ) {
        mbedtls_mutex_lock(&crypto_locks[0]);
        CMU_ClockEnable(crypto_devices[0].clock, true);
        device = crypto_devices[0].device;
    }
#endif
    if ( device == NULL ) {
        CMU_ClockEnable(crypto_devices[0].clock, true);
        device = crypto_devices[0].device;
    }

    crypto_management_critical_exit();
    return device;
}

/* Release ownership of an available crypto device */
void crypto_management_release( CRYPTO_TypeDef *device )
{
    int devno = crypto_management_index_by_device(device);
    crypto_management_critical_enter();
    CMU_ClockEnable(crypto_devices[devno].clock, false);
    /* Release device ownership mutex here */
#if defined ( MBEDTLS_THREADING_C )
    mbedtls_mutex_unlock(&crypto_locks[devno]);
#endif
    crypto_management_critical_exit();
}

/* Enter critical section on this device */
void crypto_management_critical_enter( void )
{

}

/* Exit critical section on this device */
void crypto_management_critical_exit( void )
{

}