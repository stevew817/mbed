/*
 * Copyright (c) 2016 ARM Limited, All Rights Reserved
 */

#include <mbed_assert.h>
#include "cmsis.h"
#include "cmsis_os2.h"
#include "mbed_rtos_storage.h"
#include "ns_trace.h"

#include "eventOS_scheduler.h"
#include "eventOS_event_timer.h"

#include "ns_event_loop.h"

#include "mbed.h"

#define TRACE_GROUP "evlp"

#ifdef __cplusplus
extern "C" {
#endif

#include "net_sleep.h"

#if MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION

static mbed_rtos_storage_event_flags_t event_flag_cb;
static const osEventFlagsAttr_t event_flags_attr = {
    .name = "nanostack_event_flags",
    .cb_mem = &event_flag_cb,
    .cb_size = sizeof event_flag_cb
};
static osEventFlagsId_t event_flag_id;

#else

#ifndef MBED_TZ_DEFAULT_ACCESS
#define MBED_TZ_DEFAULT_ACCESS   0
#endif

static void event_loop_thread(void *arg);

static uint64_t event_thread_stk[MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_THREAD_STACK_SIZE/8];
static mbed_rtos_storage_thread_t event_thread_tcb;
static const osThreadAttr_t event_thread_attr = {
    .name = "nanostack_event_thread",
    .attr_bits = 0,
    .cb_mem = &event_thread_tcb,
    .cb_size = sizeof event_thread_tcb,
    .stack_mem = &event_thread_stk[0],
    .stack_size = sizeof event_thread_stk,
    .priority = osPriorityNormal,
    .tz_module = MBED_TZ_DEFAULT_ACCESS,
};
#endif

#if !MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
static osThreadId_t event_thread_id;
#endif

static mbed_rtos_storage_mutex_t event_mutex;
static const osMutexAttr_t event_mutex_attr = {
  .name = "nanostack_event_mutex",
  .attr_bits = osMutexRecursive | osMutexPrioInherit | osMutexRobust,
  .cb_mem = &event_mutex,
  .cb_size = sizeof event_mutex,
};
static osMutexId_t event_mutex_id;
static osThreadId_t event_mutex_owner_id = NULL;
static uint32_t owner_count = 0;

#ifdef __cplusplus
}
#endif

void eventOS_scheduler_mutex_wait(void)
{
    osMutexAcquire(event_mutex_id, osWaitForever);
    if (0 == owner_count) {
        event_mutex_owner_id = osThreadGetId();
    }
    owner_count++;
}

void eventOS_scheduler_mutex_release(void)
{
    owner_count--;
    if (0 == owner_count) {
        event_mutex_owner_id = NULL;
    }
    osMutexRelease(event_mutex_id);
}

uint8_t eventOS_scheduler_mutex_is_owner(void)
{
    return osThreadGetId() == event_mutex_owner_id ? 1 : 0;
}

void eventOS_scheduler_signal(void)
{
    // XXX why does signal set lock if called with irqs disabled?
    //__enable_irq();
    //tr_debug("signal %p", (void*)event_thread_id);
#if MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
    osEventFlagsSet(event_flag_id, 1);
#else
    osThreadFlagsSet(event_thread_id, 1);
#endif
    //tr_debug("signalled %p", (void*)event_thread_id);
}

static LowPowerTimer lp_timer;

void eventOS_scheduler_idle(void)
{
    //tr_debug("idle");
    eventOS_scheduler_mutex_release();

#ifdef MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_SLEEPING_SCHEDULER
    uint32_t poll;

#if MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
    poll = osEventFlagsWait(event_flag_id, 1, osFlagsWaitAny, 0);
#else
    poll = osThreadFlagsWait(1, 0, 0);
#endif

    while (poll & (1 << 31)) {
        uint32_t sleep_possible = eventOS_event_timer_shortest_active_timer();
        if (sleep_possible > 1) {
            if (eventOS_scheduler_timer_stop() != 0) {
                tr_warn("EventOS timer sleep fail");
                //sleep_possible = osWaitForever;
            }
        } else {
            sleep_possible = osWaitForever;
        }

        if (sleep_possible != osWaitForever) {
            //tr_warn("sleeping event ticker %d", sleep_possible);
            lp_timer.stop();
            lp_timer.reset();
            lp_timer.start();
        }

    #if MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
        poll = osEventFlagsWait(event_flag_id, 1, osFlagsWaitAny, sleep_possible);
    #else
        poll = osThreadFlagsWait(1, 0, sleep_possible);
    #endif

        if (sleep_possible != osWaitForever) {
            lp_timer.stop();

            uint32_t ms_elapsed = lp_timer.read_ms();
            ///§tr_warn("waited %d", ms_elapsed);

            //Update Runtime ticks and event timers
            if (eventOS_scheduler_timer_synch_after_sleep(ms_elapsed) != 0) {
                tr_warn("Timer wakeUP Fail");
            }
        }
    }
#else
#if MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
    osEventFlagsWait(event_flag_id, 1, osFlagsWaitAny, osWaitForever);
#else
    osThreadFlagsWait(1, 0, osWaitForever);
#endif
#endif
    /*
    uint32_t sleep_possible = arm_net_check_enter_deep_sleep_possibility();
    if (sleep_possible) {
        uint32_t system_timer_next_tick_time = eventOS_event_timer_shortest_active_timer();
        if (system_timer_next_tick_time) {
            if (system_timer_next_tick_time < sleep_possible) {
                sleep_possible = system_timer_next_tick_time;    //Select shorter next event
            }
        }
        if (arm_net_enter_sleep() != 0) {
            tr_warn("stack preempted sleep");
            sleep_possible = osWaitForever;
        }
    } else {
        sleep_possible = osWaitForever;
    }

    if (sleep_possible != osWaitForever) {
        if (eventOS_scheduler_timer_stop() != 0) {
            tr_warn("EventOS timer sleep fail");
            //sleep_possible = osWaitForever;
        }
    }

    if (sleep_possible != osWaitForever) {
        tr_warn("sleeping %d", sleep_possible);
        lp_timer.stop();
        lp_timer.reset();
        lp_timer.start();
    }

#if MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
    osEventFlagsWait(event_flag_id, 1, osFlagsWaitAny, sleep_possible);
#else
    osThreadFlagsWait(1, 0, sleep_possible);
#endif

    if (sleep_possible != osWaitForever) {
        lp_timer.stop();

        uint32_t ms_elapsed = lp_timer.read_ms();
        tr_warn("waited %d", ms_elapsed);

        arm_net_wakeup_and_timer_synch(ms_elapsed);

        //Update Runtime ticks and event timers
        if (eventOS_scheduler_timer_synch_after_sleep(ms_elapsed) != 0) {
            tr_warn("Timer wakeUP Fail");
        }
    }
    */
    eventOS_scheduler_mutex_wait();
}

#if !MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
static void event_loop_thread(void *arg)
{
    (void)arg;
    eventOS_scheduler_mutex_wait();
    eventOS_scheduler_run(); //Does not return
}
#endif

// This is used to initialize the lock used by event loop even
// if it is not ran in a separate thread.
void ns_event_loop_init(void)
{
    event_mutex_id = osMutexNew(&event_mutex_attr);
    MBED_ASSERT(event_mutex_id != NULL);

    // If a separate event loop thread is not used, the signaling
    // happens via event flags instead of thread flags. This allows one to
    // perform the initialization from any thread and removes need to know the id
    // of event loop dispatch thread.
#if MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
    event_flag_id  = osEventFlagsNew(&event_flags_attr);
    MBED_ASSERT(event_flag_id != NULL);
#endif
}

#if !MBED_CONF_NANOSTACK_HAL_EVENT_LOOP_DISPATCH_FROM_APPLICATION
void ns_event_loop_thread_create(void)
{
    event_thread_id = osThreadNew(event_loop_thread, NULL, &event_thread_attr);
    MBED_ASSERT(event_thread_id != NULL);
}

void ns_event_loop_thread_start(void)
{
}
#endif
