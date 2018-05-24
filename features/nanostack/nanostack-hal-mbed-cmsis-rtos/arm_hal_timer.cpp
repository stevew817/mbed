/*
 * Copyright (c) 2016 ARM Limited, All Rights Reserved
 */

// Include before mbed.h to properly get UINT*_C()
#include "ns_types.h"

#include "mbed.h"
#include "platform/SingletonPtr.h"
#include "platform/arm_hal_timer.h"
#include "platform/arm_hal_interrupt.h"
#include <mbed_assert.h>

static SingletonPtr<LowPowerTimer> timer;
static SingletonPtr<LowPowerTimeout> timeout;

// If critical sections are implemented using mutexes, timers must be called in thread context, and
// we use the high-priority event queue for this.
// If critical sections disable interrupts, we can call timers directly from interrupt. Avoiding the
// event queue can save ~1600B of RAM if the rest of the system is not using the event queue either.
// Caveats of this tunable are listed on arm_hal_interrupt.c.
#if !MBED_CONF_NANOSTACK_HAL_CRITICAL_SECTION_USABLE_FROM_INTERRUPT
static EventQueue *equeue;
#endif

static uint32_t due;
static void (*arm_hal_callback)(void);

// Called once at boot
void platform_timer_enable(void)
{
#if !MBED_CONF_NANOSTACK_HAL_CRITICAL_SECTION_USABLE_FROM_INTERRUPT
    equeue = mbed_highprio_event_queue();
    MBED_ASSERT(equeue != NULL);
#endif
    // Prime the SingletonPtrs - can't construct from IRQ/critical section
    timer.get();
    timeout.get();
}

// Actually cancels a timer, not the opposite of enable
void platform_timer_disable(void)
{
    timeout->detach();
}

// Not called while running, fortunately
void platform_timer_set_cb(void (*new_fp)(void))
{
    arm_hal_callback = new_fp;
}

static void timer_callback(void)
{
    due = 0;

#if MBED_CONF_NANOSTACK_HAL_CRITICAL_SECTION_USABLE_FROM_INTERRUPT
    // Callback is interrupt safe so it can be called directly without
    // bouncing via event queue thread.
    arm_hal_callback();
#else
    equeue->call(arm_hal_callback);
#endif
}

// This is called from inside platform_enter_critical - IRQs can't happen
void platform_timer_start(uint16_t slots)
{
    timer->reset();
    due = slots * UINT32_C(50);
    timeout->attach_us(timer_callback, due);
}

// This is called from inside platform_enter_critical - IRQs can't happen
uint16_t platform_timer_get_remaining_slots(void)
{
    uint32_t elapsed = timer->read_us();
    if (elapsed < due) {
        return (uint16_t) ((due - elapsed) / 50);
    } else {
        return 0;
    }
}

#ifdef NS_EVENTLOOP_USE_TICK_TIMER
static LowPowerTicker tick_timer;
static void (*tick_timer_cbptr)(void);

// EventOS timer callback function
static void tick_timer_callback(void)
{
    if (tick_timer_cbptr != NULL) {
        tick_timer_cbptr();
    }
}

int8_t platform_tick_timer_register(void (*tick_timer_cb)(void))
{
    tick_timer_cbptr = tick_timer_cb;
    return 1;
}

int8_t platform_tick_timer_start(uint32_t period_ms)
{
    tick_timer.detach();
    tick_timer.attach_us(tick_timer_callback, period_ms*1000);
    return 0;
}

int8_t platform_tick_timer_stop(void)
{
    tick_timer.detach();
    return 0;
}
#endif // !NS_EVENTLOOP_USE_TICK_TIMER