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

#ifndef MBEDTLS_CRYPTO_MANAGEMENT_H
#define MBEDTLS_CRYPTO_MANAGEMENT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdlib.h>

#include "em_device.h"
#include "em_crypto.h"

/* Get ownership of an available crypto device */
CRYPTO_TypeDef *crypto_management_acquire( void );
/* Release ownership of an available crypto device */
void crypto_management_release( CRYPTO_TypeDef *device );

/* Enter critical section on this device */
void crypto_management_critical_enter( void );
/* Exit critical section on this device */
void crypto_management_critical_exit( void );

/* Acquire a device with preemption. NOT thread-safe! */
CRYPTO_TypeDef *crypto_management_acquire_preemption( void );
/* Release a device from preemption */
void crypto_management_release_preemption( CRYPTO_TypeDef *device );

#endif