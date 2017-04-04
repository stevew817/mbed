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
#include "em_core.h"

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
static crypto_context_t preemption_context;
static bool             is_preempted = false;
static CORE_irqState_t  preemption_irq_state = 0U;
#endif

static CORE_irqState_t  critical_irq_state = 0U;

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
    uint32_t clockMask;
} crypto_device_t;

static const crypto_device_t crypto_devices[CRYPTO_COUNT] =
{
#if defined( CRYPTO0 )
    {
        CRYPTO0,
        CMU_HFBUSCLKEN0_CRYPTO0
    },
#elif defined( CRYPTO )
    {
        CRYPTO,
        CMU_HFBUSCLKEN0_CRYPTO
    },
#endif
#if defined( CRYPTO1 )
    {
        CRYPTO1,
        CMU_HFBUSCLKEN0_CRYPTO1
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

#define CRYPTO_CLOCK_ENABLE(clk)  CMU->HFBUSCLKEN0 |= clk
#define CRYPTO_CLOCK_DISABLE(clk) CMU->HFBUSCLKEN0 &= ~clk
#define CRYPTO_CLOCK_ENABLED(clk) ((CMU->HFBUSCLKEN0 & clk) == clk)

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
#if defined( MBEDTLS_THREADING_C )
    for ( int i = 0; i < CRYPTO_COUNT; i++ ) {
        if ( 0 == mbedtls_mutex_trylock(&crypto_locks[i]) ) {
            /* Locked a device! */
            crypto_management_critical_enter();
            CRYPTO_CLOCK_ENABLE( crypto_devices[i].clockMask );
            crypto_management_critical_exit();
            device = crypto_devices[i].device;
        }
    }
    /* If no device immediately available, pend on the first one */
    if ( device == NULL ) {
        mbedtls_mutex_lock( &crypto_locks[0] );
        crypto_management_critical_enter();
        CRYPTO_CLOCK_ENABLE( crypto_devices[0].clockMask );
        crypto_management_critical_exit();
        device = crypto_devices[0].device;
    }
#endif
    if ( device == NULL ) {
        crypto_management_critical_enter();
        CRYPTO_CLOCK_ENABLE( crypto_devices[0].clockMask );
        crypto_management_critical_exit();
        device = crypto_devices[0].device;
    }

    return device;
}

/* Release ownership of an available crypto device */
void crypto_management_release( CRYPTO_TypeDef *device )
{
    int devno = crypto_management_index_by_device( device );
    crypto_management_critical_enter();
    CRYPTO_CLOCK_DISABLE( crypto_devices[devno].clockMask );
    /* Release device ownership mutex here */
#if defined ( MBEDTLS_THREADING_C )
    mbedtls_mutex_unlock( &crypto_locks[devno] );
#endif
    crypto_management_critical_exit();
}

/* Enter critical section on this device */
void crypto_management_critical_enter( void )
{
    /* Turn off interrupts that can cause preemption */
    critical_irq_state = CORE_EnterCritical();
}

/* Yield from critical section on this device */
void crypto_management_critical_yield( void )
{
    CORE_YieldCritical();
}

/* Exit critical section on this device */
void crypto_management_critical_exit( void )
{
    /* Turn interrupts back on */
    CORE_ExitCritical( critical_irq_state );
}

/* Acquire a device with preemption. NOT thread-safe! */
CRYPTO_TypeDef *crypto_management_acquire_preemption( void )
{
#if defined( MBEDTLS_CRYPTO_DEVICE_PREEMPTION )
    CRYPTO_TypeDef *device = NULL;
    /* Turn off interrupts */
    preemption_irq_state = CORE_EnterCritical();

    /* Check if there is an unused CRYPTO instance */
    for ( int i = 0; i < CRYPTO_COUNT; i++ ) {
        if ( !CRYPTO_CLOCK_ENABLED( crypto_devices[i].clockMask ) ) {
            /* Found an unused device */
            CRYPTO_CLOCK_ENABLE( crypto_devices[i].clockMask );
            device = crypto_devices[i].device;
        }
    }

    /* If there is no unused instance, preempt the last one */
    if ( device == NULL ) {
        is_preempted = true;
        device = crypto_devices[CRYPTO_COUNT - 1].device;

        /* In case this instance is still working on anything */
        CRYPTO_InstructionSequenceWait(device);

        /* Store operational context */
        preemption_context.WAC      = device->WAC;
        preemption_context.CTRL     = device->CTRL;
        preemption_context.SEQCTRL  = device->SEQCTRL;
        preemption_context.SEQCTRLB = device->SEQCTRLB;
        preemption_context.IEN      = device->IEN;
        preemption_context.SEQ[0]   = device->SEQ0;
        preemption_context.SEQ[1]   = device->SEQ1;
        preemption_context.SEQ[2]   = device->SEQ2;
        preemption_context.SEQ[3]   = device->SEQ3;
        preemption_context.SEQ[4]   = device->SEQ4;
        
        if ( (preemption_context.WAC & _CRYPTO_WAC_RESULTWIDTH_MASK) == CRYPTO_WAC_RESULTWIDTH_260BIT)
        {
            CRYPTO_DData0Read260(device, preemption_context.DDATA[0]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA1TODDATA0; /* Move DDATA1 to DDATA0
                                                              in order to read. */
            CRYPTO_DData0Read260(device, preemption_context.DDATA[1]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA2TODDATA0; /* Move DDATA2 to DDATA0
                                                              in order to read. */
            CRYPTO_DData0Read260(device, preemption_context.DDATA[2]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA3TODDATA0; /* Move DDATA3 to DDATA0
                                                              in order to read. */
            CRYPTO_DData0Read260(device, preemption_context.DDATA[3]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA4TODDATA0; /* Move DDATA4 to DDATA0
                                                              in order to read. */
            CRYPTO_DData0Read260(device, preemption_context.DDATA[4]);
        }
        else
        {
            CRYPTO_DDataRead(&device->DDATA0, preemption_context.DDATA[0]);
            CRYPTO_DDataRead(&device->DDATA1, preemption_context.DDATA[1]);
            CRYPTO_DDataRead(&device->DDATA2, preemption_context.DDATA[2]);
            CRYPTO_DDataRead(&device->DDATA3, preemption_context.DDATA[3]);
            CRYPTO_DDataRead(&device->DDATA4, preemption_context.DDATA[4]);
        }

        /* Search for possible EXEC commands and replace with END. */
        for ( size_t i = 0; i < sizeof(preemption_context.SEQ); i++ ) {
            if ( ((uint8_t*)preemption_context.SEQ)[i] == CRYPTO_CMD_INSTR_EXEC ) {
                ((uint8_t*)preemption_context.SEQ)[i] = CRYPTO_CMD_INSTR_END;
            }
        }
    }

    return device;
#else
    return crypto_management_acquire();
#endif
}

/* Release a device from preemption */
void crypto_management_release_preemption( CRYPTO_TypeDef *device )
{
#if defined( MBEDTLS_CRYPTO_DEVICE_PREEMPTION )
    if ( is_preempted ) {
        /* If we preempted something, put their context back */
        device->WAC      = preemption_context.WAC;
        device->CTRL     = preemption_context.CTRL;
        device->SEQCTRL  = preemption_context.SEQCTRL;
        device->SEQCTRLB = preemption_context.SEQCTRLB;
        device->IEN      = preemption_context.IEN;
        device->SEQ0     = preemption_context.SEQ[0];
        device->SEQ1     = preemption_context.SEQ[1];
        device->SEQ2     = preemption_context.SEQ[2];
        device->SEQ3     = preemption_context.SEQ[3];
        device->SEQ4     = preemption_context.SEQ[4];
         
        if ( (preemption_context.WAC & _CRYPTO_WAC_RESULTWIDTH_MASK) == CRYPTO_WAC_RESULTWIDTH_260BIT)
        {
            /* Start by writing the DDATA1 value to DDATA0 and move to DDATA1. */
            CRYPTO_DData0Write260(device, preemption_context.DDATA[1]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA0TODDATA1;
            
            /* Write the DDATA2 value to DDATA0 and move to DDATA2. */
            CRYPTO_DData0Write260(device, preemption_context.DDATA[2]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA0TODDATA2;
            
            /* Write the DDATA3 value to DDATA0 and move to DDATA3. */
            CRYPTO_DData0Write260(device, preemption_context.DDATA[3]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA0TODDATA3;
            
            /* Write the DDATA4 value to DDATA0 and move to DDATA4. */
            CRYPTO_DData0Write260(device, preemption_context.DDATA[4]);
            device->CMD = CRYPTO_CMD_INSTR_DDATA0TODDATA4;
            
            /* Finally write DDATA0 */
            CRYPTO_DData0Write260(device, preemption_context.DDATA[0]);
        }
        else
        {
            CRYPTO_DDataWrite(&device->DDATA0, preemption_context.DDATA[0]);
            CRYPTO_DDataWrite(&device->DDATA1, preemption_context.DDATA[1]);
            CRYPTO_DDataWrite(&device->DDATA2, preemption_context.DDATA[2]);
            CRYPTO_DDataWrite(&device->DDATA3, preemption_context.DDATA[3]);
            CRYPTO_DDataWrite(&device->DDATA4, preemption_context.DDATA[4]);
        }

        is_preempted = false;
    } else {
        /* If we didn't preempt anything, turn crypto clock back off */
        CRYPTO_CLOCK_DISABLE( crypto_devices[crypto_management_index_by_device( device )].clockMask );
    }

    /* Turn interrupts back on */
    CORE_ExitCritical( preemption_irq_state );
#else
    crypto_management_release(device);
#endif
}