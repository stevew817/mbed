/***************************************************************************//**
 * @file usbconfig.h
 * @brief USB protocol stack library, application supplied configuration options.
 * @version 3.20.12
 *******************************************************************************
 * @section License
 * <b>(C) Copyright 2014 Silicon Labs, http://www.silabs.com</b>
 *******************************************************************************
 *
 * This file is licensed under the Silabs License Agreement. See the file
 * "Silabs_License_Agreement.txt" for details. Before using this software for
 * any purpose, you must agree to the terms of that agreement.
 *
 ******************************************************************************/

#ifndef __USBCONFIG_H
#define __USBCONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Compile stack for device mode. */
#define USB_DEVICE

/* Maximum number of endpoint used, EP0 excluded. If you change this, you must
   also change USBEndpoints_EFM32.h to match. */
#define NUM_EP_USED 6

/* Power management modes. The following can be or'd toghether. See comments in
   em_usbd.c under "Energy-saving modes" for more details.

   USB_PWRSAVE_MODE_ONSUSPEND  Set USB peripheral in low power mode on suspend

   USB_PWRSAVE_MODE_ONVBUSOFF  Set USB peripheral in low power mode when not
   attached to a host. While this mode assumes that the internal voltage regulator
   is used and that the VREGI pin of the chip is connected to VBUS it should
   be safe to use given that VREGOSEN is always enabled. If you disable VREGOSEN
   you must turn this off.

   USB_PWRSAVE_MODE_ENTEREM2  Enter EM2 when USB peripheral is in low power mode.
   On Mbed this allows the sleep() and deepsleep() calls to enter EM2, but
   does not automatically enter any sleep states. Entering EM1 is always allowed.
*/
#define USB_PWRSAVE_MODE  (USB_PWRSAVE_MODE_ONSUSPEND|USB_PWRSAVE_MODE_ONVBUSOFF|USB_PWRSAVE_MODE_ENTEREM2)

/* Use dynamic memory to allocate rx/tx buffers in the HAL. Saves memory
   as buffers are only allocated for used endpoints. The system malloc
   must return memory that is aligned by 4.

   Note: if you disable this, using isochronous endpoints with packet
   sizes that are larger than the maximum for other EP types (64) will
   not work. */
#define USB_USE_DYNAMIC_MEMORY

/* When the USB peripheral is set in low power mode, it must be clocked by a 32kHz
   clock. Both LFXO and LFRCO can be used, but only LFXO guarantee USB specification
   compliance. */
#define USB_USBC_32kHz_CLK   USB_USBC_32kHz_CLK_LFXO

/* Uncomment to get some debugging information. Default value for USER_PUTCHAR
   should work for SiLabs Gecko boards. Printf requires a working retarget
   implementation for write(). */
//#define DEBUG_USB_API
//#define USB_USE_PRINTF
//#define USER_PUTCHAR   ITM_SendChar
//#define DEBUG_USB_INT_HI
//#define DEBUG_USB_INT_LO



#ifdef __cplusplus
}
#endif

#endif /* __USBCONFIG_H */
