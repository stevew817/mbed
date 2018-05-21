/*
 * Copyright (c) 2014-2017, Arm Limited and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "nsconfig.h"
#include "ns_types.h"
#include "ns_trace.h"
#include "eventOS_event.h"
#include "eventOS_callback_timer.h"
#include "NWK_INTERFACE/Include/protocol.h"
#include "NWK_INTERFACE/Include/protocol_timer.h"
#include "platform/arm_hal_interrupt.h"

#define TRACE_GROUP "ctim"

volatile NS_LARGE protocol_timer_t protocol_timer[PROTOCOL_TIMER_MAX];
static arm_event_storage_t event[PROTOCOL_TIMER_MAX];

int protocol_timer_init(void)
{
    size_t i;
    for (i = 0; i < PROTOCOL_TIMER_MAX; i++) {
        protocol_timer[i].id = -1;
        protocol_timer[i].overflow_ticks = 0;
        protocol_timer[i].allocated = false;
        protocol_timer[i].fptr = NULL;

        event[i].data.data_ptr = NULL;
        event[i].data.event_type = ARM_IN_PROTOCOL_TIMER_EVENT;
        event[i].data.event_id = 0;
        event[i].data.priority = ARM_LIB_HIGH_PRIORITY_EVENT;
    }
    return 0;
}

// time is in milliseconds
void protocol_timer_start(protocol_timer_id_t id, void (*passed_fptr)(uint16_t), uint32_t time)
{
    if(id > PROTOCOL_TIMER_MAX) {
        tr_err("Out of range protocol timer id\n");
        return;
    }

    if (passed_fptr) {
        if (protocol_timer[id].allocated == false) {
            if (protocol_timer[id].id == -1) {
                int8_t new_id = eventOS_callback_timer_register(protocol_timer_interrupt);
                if (new_id == -1) {
                    tr_err("Can't allocate new protocol timer. Check your eventOS memory?\n");
                    return;
                }
                protocol_timer[id].id = new_id;
            }
            protocol_timer[id].fptr = passed_fptr;
            protocol_timer[id].allocated = true;
            protocol_timer[id].total_time = 0;
            protocol_timer[id].overflow_ticks = (time * 20) >> 15;
            eventOS_callback_timer_start(protocol_timer[id].id, (time * 20) & 0x7FFF); // convert ms to slots
        } else {
            tr_warn("Trying to restart an already running protocol timer\n");
        }
    } else {
        tr_debug("Do Not use Null pointer for fptr!\n");
    }
}

void protocol_timer_stop(protocol_timer_id_t id)
{
    platform_enter_critical();
    if (id < PROTOCOL_TIMER_MAX) {
        if (protocol_timer[id].allocated) {
            eventOS_callback_timer_stop(protocol_timer[id].id);
            protocol_timer[id].allocated = false;
        }
    }
    platform_exit_critical();
}

void protocol_timer_sleep_balance(uint32_t time_in_ms)
{
    // No need to adjust for time here, since we're depending
    // on our running event timers
    (void)time_in_ms;
}

void protocol_timer_event_lock_free(void)
{
    // No longer required
}


void protocol_timer_cb(uint16_t ticks)
{
    if (protocol_timer[ticks].fptr) {
        void (*temp_fptr)(uint16_t) = protocol_timer[ticks].fptr;
        uint32_t temp_time = protocol_timer[ticks].total_time;
        protocol_timer[ticks].fptr = NULL;
        protocol_timer[ticks].total_time = 0;
        // protocol timer ran originally on a 50ms timer, so need to
        // report back up using a tick value instead of ms
        temp_fptr(temp_time / 50);
    }
}

void protocol_timer_interrupt(int8_t timer_id, uint16_t slots)
{
    size_t i;
    for (i = 0; i < PROTOCOL_TIMER_MAX; i++) {
        if (protocol_timer[i].id == timer_id) {
            break;
        }
    }

    if (i < PROTOCOL_TIMER_MAX) {
        if (protocol_timer[i].allocated) {
            // update running time
            protocol_timer[i].total_time += slots / 20;

            if (protocol_timer[i].overflow_ticks > 0) {
                // Check if we need to keep running
                protocol_timer[i].overflow_ticks--;
                eventOS_callback_timer_start(i, 0x7FFF);
            } else {
                // Done with this timer
                protocol_timer[i].allocated = false;
                // De-escalate from callback context
                /* Dynamic stuff */
                event[i].data.receiver = event[i].data.sender = protocol_read_tasklet_id();
                event[i].data.event_data = i;

                /* Use user-allocated variant to avoid memory allocation failure */
                eventOS_event_send_user_allocated(&event[i]);
            }
        }
    }
}
