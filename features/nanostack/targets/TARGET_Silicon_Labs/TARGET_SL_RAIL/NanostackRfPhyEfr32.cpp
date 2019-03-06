/*
 * Copyright (c) 2016 Silicon Laboratories, Inc. http://www.silabs.com
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "NanostackRfPhyEfr32.h"

#include <string.h>

#include "mbed.h"
#include "mbed_power_mgmt.h"
#include "ns_types.h"
#include "platform/arm_hal_interrupt.h"
#include "nanostack/platform/arm_hal_phy.h"
#include "mbed_toolchain.h"

/*******************************************************************************
 * Enable debug printing with SL_RADIO_DEBUG,
 * override debug printer with SL_DEBUG_PRINT.
 ******************************************************************************/
#ifdef SL_RADIO_DEBUG
#include "mbed-trace/mbed_trace.h"
#define  TRACE_GROUP  "SLRF"

#ifndef SL_DEBUG_PRINT
#define SL_DEBUG_PRINT(...) tr_debug(__VA_ARGS__)
#endif
#ifndef SL_INFO_PRINT
#define SL_INFO_PRINT(...) tr_info(__VA_ARGS__)
#endif
#ifndef SL_WARN_PRINT
#define SL_WARN_PRINT(...) tr_warn(__VA_ARGS__)
#endif
#else
#define SL_DEBUG_PRINT(...)
#define SL_INFO_PRINT(...)
#define SL_WARN_PRINT(...)
#endif

/*******************************************************************************
 * Data type constants
 ******************************************************************************/
/* 802.15.4 maximum size of a single packet including PHY byte is 128 bytes */
#define MAC_PACKET_MAX_LENGTH   128

/*******************************************************************************
 * Definitions for the adaptor thread required to de-escalate from RAIL IRQ.
 ******************************************************************************/
/* RF_THREAD_STACK_SIZE defines tack size for the RF adaptor thread */
#ifndef RF_THREAD_STACK_SIZE
#define RF_THREAD_STACK_SIZE 1024
#endif

/* RF_QUEUE_SIZE defines queue size for incoming messages */
#ifndef RF_QUEUE_SIZE
#define RF_QUEUE_SIZE  8
#endif

/* RFThreadSignal used to signal from interrupts to the adaptor thread */
enum RFThreadSignal {
    SL_RX_DONE          = (1 << 1),
    SL_TX_DONE          = (1 << 2),
    SL_TX_ERR           = (1 << 3),
    SL_TX_TIMEOUT       = (1 << 4),
    SL_ACK_RECV         = (1 << 5),
    SL_ACK_RECV_PD      = (1 << 6),
    SL_ACK_TIMEOUT      = (1 << 7),
    SL_TXFIFO_ERR       = (1 << 8),
    SL_RXFIFO_ERR       = (1 << 9),
    SL_CAL_REQ          = (1 << 10),
    SL_RSSI_DONE        = (1 << 11),
};

typedef enum {
    RADIO_UNINIT,
    RADIO_IDLE,
    RADIO_TX,
    RADIO_RX,
    RADIO_CALIBRATION,
    RADIO_ED
} siliconlabs_modem_state_t;

/*  Adaptor thread definitions */
static void rf_thread_loop(const void *arg);
static osThreadDef(rf_thread_loop, osPriorityRealtime, RF_THREAD_STACK_SIZE);
static osThreadId rf_thread_id = 0;

/*******************************************************************************
 * Nanostack-specific variables & data setup
 ******************************************************************************/
/* RF driver data */
static phy_device_driver_s device_driver;
static int8_t  rf_radio_driver_id = -1;
static uint8_t MAC_address[8];
static uint16_t PAN_address;
static uint16_t short_address;

/* Driver instance handle */
static NanostackRfPhyEfr32 *rf = NULL;

/* Channel configurations
 * This implementation statically advertises both 2.4G and Sub-G 'capabilities'
 * to Nanostack, but Sub-G may or may not be possible depending on the exact
 * chip & board in use. If Nanostack requests a channel switch to an unsupported
 * channel, then this will be reported at runtime. */
static const phy_rf_channel_configuration_s phy_24ghz = {2405000000U, 5000000U, 250000U, 16U, M_OQPSK};
static const phy_rf_channel_configuration_s phy_subghz = {868300000U, 2000000U, 250000U, 11U, M_OQPSK};

static const phy_device_channel_page_s phy_channel_pages[] = {
        { CHANNEL_PAGE_0, &phy_24ghz},
        { CHANNEL_PAGE_2, &phy_subghz},
        { CHANNEL_PAGE_0, NULL}
};

/* ARM_NWK_HAL prototypes */
static int8_t rf_extension(phy_extension_type_e extension_type, uint8_t *data_ptr);
static int8_t rf_interface_state_control(phy_interface_state_e new_state, uint8_t rf_channel);
static int8_t rf_address_write(phy_address_type_e address_type, uint8_t *address_ptr);
static int8_t rf_start_cca(uint8_t *data_ptr, uint16_t data_length, uint8_t tx_handle, data_protocol_e data_protocol );

/*******************************************************************************
 * RAIL-specific variables & data setup
 ******************************************************************************/
/* Silicon Labs headers */
extern "C" {
    #include "rail/rail.h"
    #include "rail/ieee802154/rail_ieee802154.h"
}

static const RAIL_CsmaConfig_t csma_config = RAIL_CSMA_CONFIG_802_15_4_2003_2p4_GHz_OQPSK_CSMA;

#if defined(TARGET_EFR32_1)
#include "ieee802154_subg_efr32xg1_configurator_out.h"
#elif defined(TARGET_EFR32_12)
/* TODO: Add SubG support for EFR32_12 */
#else
#error "Not a valid target."
#endif

#if MBED_CONF_SL_RAIL_HAS_SUBGIG
static RAIL_ChannelConfigEntryAttr_t entry_868;
static RAIL_ChannelConfigEntryAttr_t entry_915;
static const RAIL_ChannelConfigEntry_t entry[] = {
    {
    .phyConfigDeltaAdd = NULL, // Add this to default config for this entry
    .baseFrequency = 868300000U,
    .channelSpacing = 600000U,
    .physicalChannelOffset = 0,
    .channelNumberStart = 0,
    .channelNumberEnd = 0,
    .maxPower = RAIL_TX_POWER_MAX,
    .attr = &entry_868
  },
  {
    .phyConfigDeltaAdd = NULL, // Add this to default config for this entry
    .baseFrequency = 906000000U,
    .channelSpacing = 2000000U,
    .physicalChannelOffset = 1,
    .channelNumberStart = 1,
    .channelNumberEnd = 10,
    .maxPower = RAIL_TX_POWER_MAX,
    .attr = &entry_915
  }
};
#endif

#if MBED_CONF_SL_RAIL_BAND == 868
#if !MBED_CONF_SL_RAIL_HAS_SUBGIG
#error "Sub-Gigahertz band is not supported on this target."
#endif
static const RAIL_ChannelConfig_t channels = {
  ieee802154_config_863,
  ieee802154_config_863_min,
  &entry[0],
  1
};
#elif MBED_CONF_SL_RAIL_BAND == 915
#if !MBED_CONF_SL_RAIL_HAS_SUBGIG
#error "Sub-Gigahertz band is not supported on this target."
#endif
static const RAIL_ChannelConfig_t channels = {
  ieee802154_config_915,
  ieee802154_config_915_min,
  &entry[1],
  1
};
#elif MBED_CONF_SL_RAIL_BAND == 2400
#ifndef MBED_CONF_SL_RAIL_HAS_2P4
#error "2.4GHz band is not supported on this target."
#endif
#else
#error "sl-rail.band is not correctly defined"
#endif

#if defined (MBED_CONF_SL_RAIL_HAS_2P4)
    // Set up the PA for 2.4 GHz operation
static const RAIL_TxPowerConfig_t paInit2p4 = {
    .mode = RAIL_TX_POWER_MODE_2P4_HP,
    .voltage = 1800,
    .rampTime = 10,
  };
#endif

#if MBED_CONF_SL_RAIL_HAS_SUBGIG
    // Set up the PA for sub-GHz operation
static const RAIL_TxPowerConfig_t paInitSubGhz = {
    .mode = RAIL_TX_POWER_MODE_SUBGIG,
    .voltage = 1800,
    .rampTime = 10,
  };
#endif

static const RAIL_StateTiming_t timings = {
    .idleToRx = 100,
    // Make txToRx slightly lower than desired to make sure we get to
    // RX in time
    .txToRx = 192 - 10,
    .idleToTx = 100,
    .rxToTx = 192,
    .rxSearchTimeout = 0,
    .txToRxSearchTimeout = 0
};

static const RAIL_IEEE802154_Config_t config = {
    .addresses = NULL,
    .ackConfig = {
        .enable = true,
        .ackTimeout = 1200,
        .rxTransitions = {
            .success = RAIL_RF_STATE_RX,
            .error = RAIL_RF_STATE_RX // ignored
        },
        .txTransitions = {
            .success = RAIL_RF_STATE_RX,
            .error = RAIL_RF_STATE_RX // ignored
        }
    },
    .timings = timings,
    .framesMask = RAIL_IEEE802154_ACCEPT_STANDARD_FRAMES,
    .promiscuousMode = false,
    .isPanCoordinator = false
};

static volatile siliconlabs_modem_state_t radio_state = RADIO_UNINIT;
static volatile bool sleep_blocked = false;
static volatile int8_t channel = -1;
static volatile uint8_t current_tx_handle = 0;
static volatile uint8_t current_tx_sequence = 0;
static volatile bool waiting_for_ack = false;
static volatile bool data_pending = false, last_ack_pending_bit = false;
static volatile uint32_t last_tx = 0;
static volatile RAIL_Handle_t gRailHandle = NULL;
static uint8_t txFifo[MAC_PACKET_MAX_LENGTH * 2];
static uint8_t rxFifo[RF_QUEUE_SIZE * MAC_PACKET_MAX_LENGTH * 2];

/* Local function prototypes */
static bool rail_checkAndSwitchChannel(uint8_t channel);
static void radioEventHandler(RAIL_Handle_t railHandle, RAIL_Events_t events);

static RAIL_Config_t railCfg = { // Must never be const
  .eventsCallback = &radioEventHandler,
  .protocol = NULL, // For BLE, pointer to a RAIL_BLE_State_t. For IEEE802.15.4 this must be NULL.
  .scheduler = NULL, // For MultiProtocol, pointer to a RAIL_SchedConfig_t
};

/*******************************************************************************
 * De-escalation thread
 ******************************************************************************/
static void try_process_rx(void) {
    /* Try getting a complete RX packet from the radio buffer */
    RAIL_RxPacketInfo_t rxPacketInfo;
    RAIL_RxPacketHandle_t rxHandle = RAIL_GetRxPacketInfo(gRailHandle,
                                                          RAIL_RX_PACKET_HANDLE_OLDEST,
                                                          &rxPacketInfo);

    while (rxHandle != RAIL_RX_PACKET_HANDLE_INVALID) {
        switch (rxPacketInfo.packetStatus) {
            case RAIL_RX_PACKET_READY_SUCCESS:
                /* Get RSSI and LQI information about this packet */
                RAIL_RxPacketDetails_t rxPacketDetails;
                rxPacketDetails.timeReceived.timePosition = RAIL_PACKET_TIME_DEFAULT;
                rxPacketDetails.timeReceived.totalPacketBytes = 0;
                RAIL_GetRxPacketDetails(gRailHandle, rxHandle, &rxPacketDetails);

                /* Packet going temporarily onto stack, Nanostack will copy it
                 * once more. */
                uint8_t packetBuffer[MAC_PACKET_MAX_LENGTH];

                /* Copy packet payload from circular FIFO into contiguous memory */
                RAIL_CopyRxPacket(&packetBuffer[0], &rxPacketInfo);

                /* Release RAIL resources early */
                RAIL_ReleaseRxPacket(gRailHandle, rxHandle);

                SL_INFO_PRINT("rPKT %d", packetBuffer[0] - 2);
                device_driver.phy_rx_cb(&packetBuffer[1], /* Data payload for Nanostack starts at FCS */
                                        packetBuffer[0] - 2, /* Payload length is part of frame, but need to subtract CRC bytes */
                                        (uint8_t)rxPacketDetails.lqi,
                                        (uint8_t)rxPacketDetails.rssi,
                                        rf_radio_driver_id);
                break;
            case RAIL_RX_PACKET_NONE:
                // No more messages
                return;
            case RAIL_RX_PACKET_RECEIVING:
                // The oldest packet in the queue hasn't been received yet, so
                // we're done here.
                return;
            default:
                // Shouldn't have happened, but you never know...
                SL_WARN_PRINT("Unhandled RX packet: %d", rxPacketInfo.packetStatus);
                RAIL_ReleaseRxPacket(gRailHandle, rxHandle);
        }

        rxHandle = RAIL_GetRxPacketInfo(gRailHandle,
                                        RAIL_RX_PACKET_HANDLE_OLDEST,
                                        &rxPacketInfo);
    }
}

static void rf_thread_loop(const void *arg)
{
    SL_DEBUG_PRINT("rf_thread_loop: starting (id: %d)", (int)rf_thread_id);
    for (;;) {
        osEvent event = osSignalWait(0, osWaitForever);

        if (event.status != osEventSignal) {
            continue;
        }

        if (event.value.signals & SL_RX_DONE) {
            event.value.signals &= ~SL_RX_DONE;
            SL_DEBUG_PRINT("rf_thread_loop: RX");
            try_process_rx();
        }

        if (event.value.signals & SL_TX_DONE) {
            event.value.signals &= ~SL_TX_DONE;
            SL_DEBUG_PRINT("rf_thread_loop: TX Done");
            device_driver.phy_tx_done_cb(rf_radio_driver_id,
                    current_tx_handle,
                    PHY_LINK_TX_SUCCESS,
                    1,
                    0);
        }

        if (event.value.signals & SL_ACK_RECV) {
            event.value.signals &= ~SL_ACK_RECV;
            SL_DEBUG_PRINT("rf_thread_loop: ACK");
            device_driver.phy_tx_done_cb( rf_radio_driver_id,
                    current_tx_handle,
                    PHY_LINK_TX_DONE,
                    1,
                    0);
        }

        if (event.value.signals & SL_ACK_RECV_PD){
            event.value.signals &= ~SL_ACK_RECV_PD;
            SL_DEBUG_PRINT("rf_thread_loop: ACK PD");
            device_driver.phy_tx_done_cb( rf_radio_driver_id,
                    current_tx_handle,
                    PHY_LINK_TX_DONE_PENDING,
                    1,
                    0);
        }

        if (event.value.signals & SL_ACK_TIMEOUT) {
            event.value.signals &= ~SL_ACK_TIMEOUT;
            SL_DEBUG_PRINT("rf_thread_loop: ACK timeout");
            device_driver.phy_tx_done_cb(rf_radio_driver_id,
                    current_tx_handle,
                    PHY_LINK_TX_FAIL,
                    1,
                    0);
        }

        if(event.value.signals & SL_TX_ERR) {
            event.value.signals &= ~SL_TX_ERR;
            SL_DEBUG_PRINT("rf_thread_loop: TX ERR");
            device_driver.phy_tx_done_cb( rf_radio_driver_id,
                    current_tx_handle,
                    PHY_LINK_TX_FAIL,
                    1,
                    0);
        }

        if(event.value.signals & SL_TX_TIMEOUT) {
            event.value.signals &= ~SL_TX_TIMEOUT;
            SL_DEBUG_PRINT("rf_thread_loop: TX timeout");
            device_driver.phy_tx_done_cb( rf_radio_driver_id,
                    current_tx_handle,
                    PHY_LINK_CCA_FAIL,
                    csma_config.csmaTries,
                    0);
        }

        if(event.value.signals & SL_CAL_REQ) {
            event.value.signals &= ~SL_CAL_REQ;
            SL_DEBUG_PRINT("rf_thread_loop: calibrating");
            RAIL_Calibrate(gRailHandle, NULL, RAIL_CAL_ALL_PENDING);
        }

        if(event.value.signals & SL_RSSI_DONE) {
            event.value.signals &= ~SL_RSSI_DONE;
            SL_DEBUG_PRINT("RSSI done (%d)", RAIL_GetAverageRssi(gRailHandle));
        }

        if(event.value.signals & SL_RXFIFO_ERR) {
            event.value.signals &= ~SL_RXFIFO_ERR;
            SL_WARN_PRINT("rf_thread_loop: SL_RXFIFO_ERR signal received (unhandled)");
        }

        if(event.value.signals & SL_TXFIFO_ERR) {
            event.value.signals &= ~SL_TXFIFO_ERR;
            SL_WARN_PRINT("rf_thread_loop: SL_TXFIFO_ERR signal received (unhandled)");
        }

        if(event.value.signals) {
            SL_WARN_PRINT("rf_thread_loop unhandled event status: %d value: %d", event.status, (int)event.value.signals);
        }

        /* Try processing for RX once more to clear potential hiccups */
        try_process_rx();
    }
}

/*============ CODE =========*/

/*
 * \brief Function initialises and registers the RF driver.
 *
 * \param none
 *
 * \return rf_radio_driver_id Driver ID given by NET library
 */
static int8_t rf_device_register(void)
{
    // If we already exist, bail.
    if(radio_state != RADIO_UNINIT) {
        return -1;
    }

    SL_DEBUG_PRINT("rf_device_register: entry");

    // Set up RAIL
    // Initialize the RAIL library and any internal state it requires
    gRailHandle = RAIL_Init(&railCfg, NULL);

    // Configure calibration settings
    RAIL_ConfigCal(gRailHandle, RAIL_CAL_ALL);

    // Set up library for IEEE802.15.4 PHY operation
#if (MBED_CONF_SL_RAIL_BAND == 2400)
    RAIL_IEEE802154_Config2p4GHzRadio(gRailHandle);
    channel = 11;
#elif (MBED_CONF_SL_RAIL_BAND == 915)
    RAIL_ConfigChannels(gRailHandle, &channels, NULL);
    channel = 1;
#elif (MBED_CONF_SL_RAIL_BAND == 868)
    RAIL_ConfigChannels(gRailHandle, &channels, NULL);
    channel = 0;
#endif

    // Enable 802.15.4 acceleration features
    if (RAIL_IEEE802154_Init(gRailHandle, &config) != RAIL_STATUS_NO_ERROR) {
        MBED_ERROR(MBED_ERROR_UNSUPPORTED, "This chip does not support 802.15.4");
    }

    // Fire all events by default
    RAIL_ConfigEvents(gRailHandle,
                      RAIL_EVENTS_ALL,
                      RAIL_EVENTS_ALL);

    // Setup the transmit buffer
    RAIL_SetTxFifo(gRailHandle, txFifo, 0, sizeof(txFifo));
    uint16_t rxSize = sizeof(rxFifo);
    RAIL_SetRxFifo(gRailHandle, rxFifo, &rxSize);

#if MBED_CONF_SL_RAIL_BAND == 2400
    if (RAIL_ConfigTxPower(gRailHandle, &paInit2p4) != RAIL_STATUS_NO_ERROR) {
        MBED_ERROR(MBED_ERROR_UNSUPPORTED, "The PA could not be initialized due to an improper configuration");
    }
#elif (MBED_CONF_SL_RAIL_BAND == 915) || (MBED_CONF_SL_RAIL_BAND == 868)
    if (RAIL_ConfigTxPower(gRailHandle, &paInitSubGhz) != RAIL_STATUS_NO_ERROR) {
        MBED_ERROR(MBED_ERROR_UNSUPPORTED, "The PA could not be initialized due to an improper configuration");
    }
#endif
    // Set the output power to the maximum supported by this chip
    if (RAIL_SetTxPowerDbm(gRailHandle, RAIL_TX_POWER_MAX) != RAIL_STATUS_NO_ERROR) {
        MBED_ERROR(MBED_ERROR_UNSUPPORTED, "The PA power could not be set");
    }

    // Set up PTI since it makes life so much easier
#if defined(MBED_CONF_SL_RAIL_PTI) && (MBED_CONF_SL_RAIL_PTI == 1)
    RAIL_PtiConfig_t ptiConfig = {
        MBED_CONF_SL_RAIL_PTI_MODE,
        MBED_CONF_SL_RAIL_PTI_BAUDRATE,
        MBED_CONF_SL_RAIL_PTI_DOUT_LOCATION,
        MBED_CONF_SL_RAIL_PTI_DOUT_PORT,
        MBED_CONF_SL_RAIL_PTI_DOUT_PIN,
        MBED_CONF_SL_RAIL_PTI_DCLK_LOCATION,
        MBED_CONF_SL_RAIL_PTI_DCLK_PORT,
        MBED_CONF_SL_RAIL_PTI_DCLK_PIN,
        MBED_CONF_SL_RAIL_PTI_DFRAME_LOCATION,
        MBED_CONF_SL_RAIL_PTI_DFRAME_PORT,
        MBED_CONF_SL_RAIL_PTI_DFRAME_PIN
    };

    // Initialize the Packet Trace Interface (PTI) for the EFR32
    RAIL_ConfigPti(gRailHandle, &ptiConfig);
    // Enable Packet Trace (PTI)
    RAIL_EnablePti(gRailHandle, true);
#endif

    /* Get real MAC address */
    /* MAC is stored MSB first */
    memcpy(MAC_address, (const void*)&DEVINFO->UNIQUEH, 4);
    memcpy(&MAC_address[4], (const void*)&DEVINFO->UNIQUEL, 4);

    /*Set pointer to MAC address*/
    device_driver.PHY_MAC = MAC_address;
    device_driver.driver_description = (char*)"EFR32_154";

    /*Type of RF PHY*/
#if MBED_CONF_SL_RAIL_BAND == 2400
    device_driver.link_type = PHY_LINK_15_4_2_4GHZ_TYPE;
#elif (MBED_CONF_SL_RAIL_BAND == 915) || (MBED_CONF_SL_RAIL_BAND == 868)
    device_driver.link_type = PHY_LINK_15_4_SUBGHZ_TYPE;
#endif

    device_driver.phy_channel_pages = phy_channel_pages;
    /*Maximum size of payload is 127*/
    device_driver.phy_MTU = 127;
    /*1 byte header in PHY layer (length)*/
    device_driver.phy_header_length = 1;
    /*No tail in PHY layer*/
    device_driver.phy_tail_length = 0;
    /*Set address write function*/
    device_driver.address_write = &rf_address_write;
    /*Set RF extension function*/
    device_driver.extension = &rf_extension;
    /*Set RF state control function*/
    device_driver.state_control = &rf_interface_state_control;
    /*Set transmit function*/
    device_driver.tx = &rf_start_cca;
    /*Upper layer callbacks init to NULL, get populated by arm_net_phy_register*/
    device_driver.phy_rx_cb = NULL;
    device_driver.phy_tx_done_cb = NULL;
    /*Virtual upper data callback init to NULL*/
    device_driver.arm_net_virtual_rx_cb = NULL;
    device_driver.arm_net_virtual_tx_cb = NULL;

    /*Register device driver*/
    rf_radio_driver_id = arm_net_phy_register(&device_driver);

    radio_state = RADIO_IDLE;

#ifdef MBED_CONF_RTOS_PRESENT
    rf_thread_id = osThreadCreate(osThread(rf_thread_loop), NULL);
#endif

    return rf_radio_driver_id;
}

/*
 * \brief Function unregisters the RF driver.
 *
 * \param none
 *
 * \return none
 */
static void rf_device_unregister(void)
{
    arm_net_phy_unregister(rf_radio_driver_id);
    if(sleep_blocked) {
        sleep_manager_unlock_deep_sleep();
        sleep_blocked = false;
    }
}

/*
 * \brief Function starts the CCA process before starting data transmission and copies the data to RF TX FIFO.
 *
 * \param data_ptr Pointer to TX data
 * \param data_length Length of the TX data
 * \param tx_handle Handle to transmission
 * \return 0 Success
 * \return -1 Busy
 */
static int8_t rf_start_cca(uint8_t *data_ptr, uint16_t data_length, uint8_t tx_handle, data_protocol_e data_protocol )
{
    switch(radio_state) {
    case RADIO_UNINIT:
        SL_WARN_PRINT("Trying to send with uninitialized radio");
        return -1;
    case RADIO_CALIBRATION:
        SL_DEBUG_PRINT("Trying to send while calibrating");
        return -1;
    case RADIO_ED:
        SL_WARN_PRINT("Trying to send while in energy detecting mode");
        return -1;
    case RADIO_TX:
        SL_WARN_PRINT("Trying to send while still sending");
        return -1;
    case RADIO_IDLE:
    case RADIO_RX:
        // If we're still waiting for an ACK, don't mess up the internal state
        if(waiting_for_ack || RAIL_GetRadioState(gRailHandle) == RAIL_RF_STATE_TX) {
            if((RAIL_GetTime() - last_tx) < 30000) {
                SL_WARN_PRINT("Trying to send while waiting on previous ACK");
                return -1;
            } else {
                SL_DEBUG_PRINT("Assuming ACK timed out");
            }
        }

        RAIL_TxOptions_t txOpt = RAIL_TX_OPTIONS_DEFAULT;
        //Check to see whether we'll be waiting for an ACK
        if(data_ptr[1] & (1 << 5)) {
            txOpt |= RAIL_TX_OPTION_WAIT_FOR_ACK;
            waiting_for_ack = true;
        } else {
            waiting_for_ack = false;
        }

        SL_INFO_PRINT("Transmitting len %d, chan %d, ack %d", data_length, channel, waiting_for_ack ? 1 : 0);

        platform_enter_critical();

        /* Since we set up Nanostack to give us a 1-byte PHY header, we get the one extra byte at the start of data_ptr
         * and need to populate it with the MAC-frame length byte (including the 2-byte hardware-inserted CRC) */
        data_ptr[0] = data_length + 2;

        RAIL_Idle(gRailHandle, RAIL_IDLE_ABORT, true);
        RAIL_WriteTxFifo(gRailHandle, data_ptr, data_length + 1, true);
        radio_state = RADIO_TX;

        if(RAIL_StartCcaCsmaTx(gRailHandle, channel, txOpt, &csma_config, NULL) == 0) {
          //Save packet number and sequence
          current_tx_handle = tx_handle;
          current_tx_sequence = data_ptr[3];
          platform_exit_critical();
          return 0;
        } else {
          RAIL_Idle(gRailHandle, RAIL_IDLE_ABORT, true);
          RAIL_StartRx(gRailHandle, channel, NULL);
          radio_state = RADIO_RX;
          platform_exit_critical();
          return -1;
        }
    }
    //Should never get here...
    return -1;
}

/*
 * \brief Function gives the control of RF states to MAC.
 *
 * \param new_state RF state
 * \param rf_channel RF channel
 *
 * \return 0 Success
 */
static int8_t rf_interface_state_control(phy_interface_state_e new_state, uint8_t rf_channel)
{
    int8_t ret_val = 0;
    switch (new_state)
    {
        /* Reset PHY driver and set to idle */
        case PHY_INTERFACE_RESET:
            RAIL_Idle(gRailHandle, RAIL_IDLE_FORCE_SHUTDOWN_CLEAR_FLAGS, true);
            radio_state = RADIO_IDLE;
            if(sleep_blocked) {
                sleep_manager_unlock_deep_sleep();
                sleep_blocked = false;
            }
            break;
        /* Disable PHY Interface driver */
        case PHY_INTERFACE_DOWN:
            RAIL_Idle(gRailHandle, RAIL_IDLE_FORCE_SHUTDOWN_CLEAR_FLAGS, true);
            radio_state = RADIO_IDLE;
            if(sleep_blocked) {
                sleep_manager_unlock_deep_sleep();
                sleep_blocked = false;
            }
            break;
        /* Enable RX */
        case PHY_INTERFACE_UP:
            if(rail_checkAndSwitchChannel(rf_channel)) {
                RAIL_Idle(gRailHandle, RAIL_IDLE_FORCE_SHUTDOWN_CLEAR_FLAGS, true);
                RAIL_IEEE802154_SetPromiscuousMode(gRailHandle, false);
                RAIL_StartRx(gRailHandle, channel, NULL);
                radio_state = RADIO_RX;
                if(!sleep_blocked) {
                    /* RX can only happen in EM0/1*/
                    sleep_manager_lock_deep_sleep();
                    sleep_blocked = true;
                }
            } else {
                ret_val = -1;
            }
            break;
        /* Enable wireless interface ED scan mode */
        case PHY_INTERFACE_RX_ENERGY_STATE:
            SL_WARN_PRINT("Unimplemented Energy Detection");
            // TODO: implement energy detection
            break;
        /* Enable RX in promiscuous mode (aka no address filtering) */
        case PHY_INTERFACE_SNIFFER_STATE:
            if(rail_checkAndSwitchChannel(rf_channel)) {
                RAIL_Idle(gRailHandle, RAIL_IDLE_FORCE_SHUTDOWN_CLEAR_FLAGS, true);
                RAIL_IEEE802154_SetPromiscuousMode(gRailHandle, true);
                RAIL_StartRx(gRailHandle, channel, NULL);
                radio_state = RADIO_RX;
                if(!sleep_blocked) {
                    /* RX can only happen in EM0/1*/
                    sleep_manager_lock_deep_sleep();
                    sleep_blocked = true;
                }
            } else {
                ret_val = -1;
            }
            break;
    }
    return ret_val;
}

/*
 * \brief Function controls the ACK pending, channel setting and energy detection.
 *
 * \param extension_type Type of control
 * \param data_ptr Data from NET library
 *
 * \return 0 Success
 */
static int8_t rf_extension(phy_extension_type_e extension_type, uint8_t *data_ptr)
{
    switch (extension_type)
    {
        /* Control MAC pending bit for Indirect data transmission */
        case PHY_EXTENSION_CTRL_PENDING_BIT:
            if(*data_ptr) {
                data_pending = true;
            } else {
                data_pending = false;
            }
            break;
        /* Return frame pending bit from last received ACK */
        case PHY_EXTENSION_READ_LAST_ACK_PENDING_STATUS:
            if(last_ack_pending_bit) {
                *data_ptr = 0xFF;
            } else {
                *data_ptr = 0;
            }
            break;
        /* Set channel */
        case PHY_EXTENSION_SET_CHANNEL:
            channel = *data_ptr;
            break;
        /* Read energy on the channel */
        case PHY_EXTENSION_READ_CHANNEL_ENERGY:
            // TODO: implement energy detection
            *data_ptr = 0;
            break;
        /* Read status of the link */
        case PHY_EXTENSION_READ_LINK_STATUS:
            // TODO: return accurate value here
            SL_WARN_PRINT("Unimplemented: Trying to read link status");
            break;
        /* Convert between LQI and RSSI */
        case PHY_EXTENSION_CONVERT_SIGNAL_INFO:
            // TODO: return accurate value here
            SL_WARN_PRINT("Unimplemented: Trying to read signal info");
            break;
        case PHY_EXTENSION_ACCEPT_ANY_BEACON:
            SL_WARN_PRINT("Unimplemented: Trying to accept any beacon");
            break;
    }
    return 0;
}

/*
 * \brief Function sets the addresses to RF address filters.
 *
 * \param address_type Type of address
 * \param address_ptr Pointer to given address
 *
 * \return 0 Success
 */
static int8_t rf_address_write(phy_address_type_e address_type, uint8_t *address_ptr)
{
    int8_t ret_val = 0;
    switch (address_type)
    {
        /*Set 48-bit address*/
        case PHY_MAC_48BIT:
            // 15.4 does not support 48-bit addressing
            ret_val = -1;
            break;
        /*Set 64-bit MAC address*/
        case PHY_MAC_64BIT:
            /* Store MAC in MSB order */
            memcpy(MAC_address, address_ptr, 8);
            SL_DEBUG_PRINT("rf_address_write: MACw ");
            for(unsigned int i = 0; i < sizeof(MAC_address); i ++) {
                SL_DEBUG_PRINT("%02x:", MAC_address[i]);
            }
            /* Pass MAC to the RF driver in LSB order */
            uint8_t MAC_reversed[8];
            for(unsigned int i = 0; i < sizeof(MAC_address); i ++) {
                MAC_reversed[i] = MAC_address[sizeof(MAC_address) - 1 - i];
            }
            RAIL_IEEE802154_SetLongAddress(gRailHandle, MAC_reversed, 0);
            break;
        /*Set 16-bit address*/
        case PHY_MAC_16BIT:
            short_address = address_ptr[0] << 8 | address_ptr[1];
            SL_DEBUG_PRINT("Set short ID %d", short_address);
            RAIL_IEEE802154_SetShortAddress(gRailHandle, short_address, 0);
            break;
        /*Set PAN Id*/
        case PHY_MAC_PANID:
            PAN_address = address_ptr[0] << 8 | address_ptr[1];
            SL_DEBUG_PRINT("Set PAN ID %d", PAN_address);
            RAIL_IEEE802154_SetPanId(gRailHandle, PAN_address, 0);
            break;
    }
    return ret_val;
}

/*******************************************************************************
 * NanostackRfPhy object boilerplate
 ******************************************************************************/
NanostackRfPhyEfr32::NanostackRfPhyEfr32() : NanostackRfPhy()
{
    // Do nothing
}

NanostackRfPhyEfr32::~NanostackRfPhyEfr32()
{
    rf_unregister();
}

int8_t NanostackRfPhyEfr32::rf_register()
{

    platform_enter_critical();

    if (rf != NULL) {
        platform_exit_critical();
        error("Multiple registrations of NanostackRfPhyEfr32 not supported");
        return -1;
    }
    int8_t radio_id = rf_device_register();
    if (radio_id < 0) {
        rf = NULL;
    } else {
        rf = this;
    }

    platform_exit_critical();
    return radio_id;
}

void NanostackRfPhyEfr32::rf_unregister()
{
    platform_enter_critical();

    if (rf != this) {
        platform_exit_critical();
        return;
    }

    rf_device_unregister();
    rf = NULL;

    platform_exit_critical();
}

void NanostackRfPhyEfr32::get_mac_address(uint8_t *mac)
{
    SL_WARN_PRINT("Starting radio with driver version %08x", get_driver_version());

    platform_enter_critical();

    memcpy(mac, MAC_address, sizeof(MAC_address));

    platform_exit_critical();
}

void NanostackRfPhyEfr32::set_mac_address(uint8_t *mac)
{
    platform_enter_critical();

    if (NULL != rf) {
        error("NanostackRfPhyEfr32 cannot change mac address when running");
        platform_exit_critical();
        return;
    }

    memcpy(MAC_address, mac, sizeof(MAC_address));

    platform_exit_critical();
}

NanostackRfPhy &NanostackRfPhy::get_default_instance()
{
    static NanostackRfPhyEfr32 rf_phy;
    return rf_phy;
}

uint32_t NanostackRfPhyEfr32::get_driver_version()
{
    RAIL_Version_t railversion;
    RAIL_GetVersion(&railversion, false);

    return (railversion.major << 24) |
           (railversion.minor << 16) |
           (railversion.rev   << 8)  |
           (railversion.build);
}

/**
 * Function to check the requested channel against the current channel,
 * and change the radio configuration if necessary.
 *
 * @param channel The new channel number requested
 * @return bool True if able to switch to the requested channel
 *
 */
static bool rail_checkAndSwitchChannel(uint8_t newChannel) {
    if(channel == newChannel) {
        return true;
    }

    if(newChannel > 0 && newChannel < 11) {
        if(MBED_CONF_SL_RAIL_BAND == 915) {
            channel = newChannel;
            return true;
        } else {
            return false;
        }
    } else if(newChannel >= 11 && newChannel <= 26) {
        if(MBED_CONF_SL_RAIL_BAND == 2400) {
            channel = newChannel;
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

/*******************************************************************************
 * IRQ (event) handling
 ******************************************************************************/
/**
 * Event handler for RAIL-fired events. Usually gets called from IRQ context.
 * Due to IRQ latency and tailchaining, multiple event flags might be set simultaneously,
 * so we have to check all of them */
static void radioEventHandler(RAIL_Handle_t railHandle,
                              RAIL_Events_t events)
{
    /* RAIL_Events_t is a 64-bit event mask, but a thread only supports 32
     * signal bits. This means we have to convert from a RAIL event mask to
     * our own custom event mask. */
    if (railHandle != gRailHandle)
        return;

#ifdef MBED_CONF_RTOS_PRESENT
    if(rf_thread_id == 0) {
        return;
    }
#endif

    size_t index = 0;
    do {
        if (events & 1ull) {
            switch(index) {
            /*
            * Occurs when the AGC averaged RSSI is done.
            * It occurs in response to RAIL_StartAverageRssi() to indicate that the
            * hardware has completed averaging. Call \ref RAIL_GetAverageRssi to get the
            * result.
            */
            case RAIL_EVENT_RSSI_AVERAGE_DONE_SHIFT:
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_RSSI_DONE);
#else
                SL_DEBUG_PRINT("RSSI done (%d)", RAIL_GetAverageRssi(gRailHandle));
#endif
                break;
            /*
            * Notifies the application when searching for an ACK has timed
            * out. This event occurs whenever the timeout for searching for an
            * ACK is exceeded.
            */
            case RAIL_EVENT_RX_ACK_TIMEOUT_SHIFT:
                if(waiting_for_ack) {
                    waiting_for_ack = false;
#ifdef MBED_CONF_RTOS_PRESENT
                    osSignalSet(rf_thread_id, SL_ACK_TIMEOUT);
#else
                    device_driver.phy_tx_done_cb( rf_radio_driver_id,
                                                  current_tx_handle,
                                                  PHY_LINK_TX_FAIL,
                                                  1,
                                                  0);
#endif
                }
                break;
            /*
            * Occurs when the receive FIFO exceeds the configured threshold
            * value. Call \ref RAIL_GetRxFifoBytesAvailable to get the number of bytes
            * available.
            */
            case RAIL_EVENT_RX_FIFO_ALMOST_FULL_SHIFT:
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_RXFIFO_ERR);
#else
                SL_DEBUG_PRINT("RX near full (%d)", RAIL_GetRxFifoBytesAvailable(gRailHandle));
#endif
                break;
            /*
            * Occurs whenever a packet is received.
            * Call RAIL_GetRxPacketInfo() to get basic packet information along
            * with a handle to this packet for subsequent use with
            * RAIL_PeekRxPacket(), RAIL_GetRxPacketDetails(),
            * RAIL_HoldRxPacket(), and RAIL_ReleaseRxPacket() as needed.
            *
            * If \ref RAIL_RX_OPTION_IGNORE_CRC_ERRORS is set, this event also occurs
            * for packets with CRC errors.
            */
            case RAIL_EVENT_RX_PACKET_RECEIVED_SHIFT:
                {
                    /* Get RX packet that got signaled */
                    RAIL_RxPacketInfo_t rxPacketInfo;
                    RAIL_RxPacketHandle_t rxHandle = RAIL_GetRxPacketInfo(gRailHandle,
                                                                          RAIL_RX_PACKET_HANDLE_NEWEST,
                                                                          &rxPacketInfo
                                                                          );

                    /* Only process the packet if it had a correct CRC */
                    if(rxPacketInfo.packetStatus == RAIL_RX_PACKET_READY_SUCCESS) {
                        uint8_t header[4];
                        RAIL_PeekRxPacket(gRailHandle, rxHandle, header, 4, 0);

                        /* If this is an ACK, deal with it early */
                        if( (header[0] == 5) &&
                            (header[3] == current_tx_sequence)  &&
                            waiting_for_ack) {
                            waiting_for_ack = false;
                            /* Save the pending bit */
                            last_ack_pending_bit = (header[1] & (1 << 4)) != 0;
                            /* Release packet */
                            RAIL_ReleaseRxPacket(gRailHandle, rxHandle);
                            /* Tell the stack we got an ACK */
#ifdef MBED_CONF_RTOS_PRESENT
                            if (last_ack_pending_bit) {
                                osSignalSet(rf_thread_id, SL_ACK_RECV_PD);
                            } else {
                                osSignalSet(rf_thread_id, SL_ACK_RECV);
                            }
#else
                            SL_DEBUG_PRINT("rACK");
                            device_driver.phy_tx_done_cb( rf_radio_driver_id,
                                                          current_tx_handle,
                                                          last_ack_pending_bit ? PHY_LINK_TX_DONE_PENDING : PHY_LINK_TX_DONE,
                                                          1,
                                                          1);
#endif
                        } else {
#ifdef MBED_CONF_RTOS_PRESENT
                            RAIL_HoldRxPacket(gRailHandle);
                            osSignalSet(rf_thread_id, SL_RX_DONE);
#else
                            /* Get RSSI and LQI information about this packet */
                            RAIL_RxPacketDetails_t rxPacketDetails;
                            rxPacketDetails.timeReceived.timePosition = RAIL_PACKET_TIME_DEFAULT;
                            rxPacketDetails.timeReceived.totalPacketBytes = 0;
                            RAIL_GetRxPacketDetails(gRailHandle, rxHandle, &rxPacketDetails);

                            /* Packet going temporarily onto stack for bare-metal apps */
                            uint8_t packetBuffer[MAC_PACKET_MAX_LENGTH];

                            /* Copy packet payload from circular FIFO into contiguous memory */
                            RAIL_CopyRxPacket(&packetBuffer[0], &rxPacketInfo);

                            /* Release RAIL resources early */
                            RAIL_ReleaseRxPacket(gRailHandle, rxHandle);

                            SL_DEBUG_PRINT("rPKT %d", packetBuffer[0] - 2);
                            device_driver.phy_rx_cb(&packetBuffer[1], /* Data payload for Nanostack starts at FCS */
                                                    packetBuffer[0] - 2, /* Payload length is part of frame, but need to subtract CRC bytes */
                                                    (uint8_t)rxPacketDetails.lqi,
                                                    (uint8_t)rxPacketDetails.rssi,
                                                    rf_radio_driver_id);
#endif
                        }
                    }
                }
                break;
            /* Event for preamble detection */
            case RAIL_EVENT_RX_PREAMBLE_DETECT_SHIFT:
                break;
            /* Event for detection of the first sync word */
            case RAIL_EVENT_RX_SYNC1_DETECT_SHIFT:
                break;
            /** Event for detection of the second sync word */
            case RAIL_EVENT_RX_SYNC2_DETECT_SHIFT:
                break;
            /* Event for detection of frame errors
            *
            * For efr32xg1x parts, frame errors include violations of variable length
            * minimum/maximum limits, frame coding errors, and CRC errors. If \ref
            * RAIL_RX_OPTION_IGNORE_CRC_ERRORS is set, \ref RAIL_EVENT_RX_FRAME_ERROR
            * will not occur for CRC errors.
            */
            case RAIL_EVENT_RX_FRAME_ERROR_SHIFT:
                break;
            /* Occurs when RX buffer is full */
            case RAIL_EVENT_RX_FIFO_OVERFLOW_SHIFT:
                break;
            /* Occurs when a packet is address filtered */
            case RAIL_EVENT_RX_ADDRESS_FILTERED_SHIFT:
                break;
            /* Occurs when an RX event times out */
            case RAIL_EVENT_RX_TIMEOUT_SHIFT:
                break;
            /* Occurs when the scheduled RX window ends */
            case RAIL_EVENT_RX_SCHEDULED_RX_END_SHIFT:
                break;
            /* An event for an aborted packet. It is triggered when a more specific
            *  reason isn't known for why the packet was aborted (e.g.
            *  \ref RAIL_EVENT_RX_ADDRESS_FILTERED). */
            case RAIL_EVENT_RX_PACKET_ABORTED_SHIFT:
                break;
            /*
            * Occurs when the packet has passed any configured address and frame
            * filtering options.
            */
            case RAIL_EVENT_RX_FILTER_PASSED_SHIFT:
                break;
            /* Occurs when modem timing is lost */
            case RAIL_EVENT_RX_TIMING_LOST_SHIFT:
                break;
            /* Occurs when modem timing is detected */
            case RAIL_EVENT_RX_TIMING_DETECT_SHIFT:
                break;
            /*
            * Indicates a Data Request is being received when using IEEE 802.15.4
            * functionality. This occurs when the command byte of an incoming frame is
            * for a data request, which requests an ACK. This callback is called before
            * the packet is fully received to allow the node to have more time to decide
            * whether to set the frame pending in the outgoing ACK. This event only ever
            * occurs if the RAIL IEEE 802.15.4 functionality is enabled.
            *
            * Call \ref RAIL_IEEE802154_GetAddress to get the source address of the
            * packet.
            */
            case RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND_SHIFT:
                if(data_pending) {
                    RAIL_IEEE802154_SetFramePending(gRailHandle);
                }
                break;

            // TX Event Bitmasks

            /*
            * Occurs when the transmit FIFO falls under the configured
            * threshold value. It only occurs if a rising edge occurs across this
            * threshold. This event does not occur on initailization or after resetting
            * the transmit FIFO with RAIL_ResetFifo().
            * Call \ref RAIL_GetTxFifoSpaceAvailable to get the number of bytes
            * available in the transmit FIFO at the time of the callback dispatch.
            */
            case RAIL_EVENT_TX_FIFO_ALMOST_EMPTY_SHIFT:
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_TXFIFO_ERR);
#else
                SL_DEBUG_PRINT("TX near empty (%d)", spaceAvailable);
#endif
                break;
            /*
            * Interrupt level event to signify when the packet was sent.
            * Call RAIL_GetTxPacketDetails() to get information about the packet
            * that was transmitted.
            * @note that this structure is only valid during the timeframe of the
            *   \ref RAIL_Config_t::eventsCallback.
            */
            case RAIL_EVENT_TX_PACKET_SENT_SHIFT:
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_TX_DONE);
#else
                if(device_driver.phy_tx_done_cb != NULL) {
                    device_driver.phy_tx_done_cb( rf_radio_driver_id,
                                                  current_tx_handle,
                                                  // Normally we'd switch on ACK requested here, but Nanostack does that for us.
                                                  PHY_LINK_TX_SUCCESS,
                                                  // Succeeded, so how many times we tried is really not relevant.
                                                  1,
                                                  0);
                }
#endif
                last_tx = RAIL_GetTime();
                radio_state = RADIO_RX;
                break;
            /*
            * An interrupt level event to signify when the packet was sent.
            * Call RAIL_GetTxPacketDetails() to get information about the packet
            * that was transmitted.
            * @note This structure is only valid during the timeframe of the
            *   \ref RAIL_Config_t::eventsCallback.
            */
            case RAIL_EVENT_TXACK_PACKET_SENT_SHIFT:
                break;
            /* Occurs when a TX is aborted by the user */
            case RAIL_EVENT_TX_ABORTED_SHIFT:
                waiting_for_ack = false;
                radio_state = RADIO_RX;
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_TX_ERR);
#else
                device_driver.phy_tx_done_cb(rf_radio_driver_id,
                                              current_tx_handle,
                                              PHY_LINK_TX_FAIL,
                                              1,
                                              0);
#endif
                break;
            /* Occurs when a TX ACK is aborted by the user */
            case RAIL_EVENT_TXACK_ABORTED_SHIFT:
                break;
            /* Occurs when a TX is blocked by something like PTA or RHO */
            case RAIL_EVENT_TX_BLOCKED_SHIFT:
                waiting_for_ack = false;
                radio_state = RADIO_RX;
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_TX_ERR);
#else
                device_driver.phy_tx_done_cb(rf_radio_driver_id,
                                              current_tx_handle,
                                              PHY_LINK_TX_FAIL,
                                              1,
                                              0);
#endif
                break;
            /* Occurs when a TX ACK is blocked by something like PTA or RHO */
            case RAIL_EVENT_TXACK_BLOCKED_SHIFT:
                break;
            /* Occurs when the TX buffer underflows */
            case RAIL_EVENT_TX_UNDERFLOW_SHIFT:
                waiting_for_ack = false;
                radio_state = RADIO_RX;
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_TX_ERR);
#else
                device_driver.phy_tx_done_cb(rf_radio_driver_id,
                                              current_tx_handle,
                                              PHY_LINK_TX_FAIL,
                                              1,
                                              0);
#endif
                break;
            /* Occurs when the buffer used for TX acking underflows */
            case RAIL_EVENT_TXACK_UNDERFLOW_SHIFT:
                MBED_ERROR(MBED_ERROR_UNDERFLOW, "TX ACK underflow");
                break;
            /* Occurs when CCA/CSMA/LBT succeeds */
            case RAIL_EVENT_TX_CHANNEL_CLEAR_SHIFT:
                break;
            /* Occurs when CCA/CSMA/LBT fails */
            case RAIL_EVENT_TX_CHANNEL_BUSY_SHIFT:
                waiting_for_ack = false;
                radio_state = RADIO_RX;
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_TX_TIMEOUT);
#else
                device_driver.phy_tx_done_cb(rf_radio_driver_id,
                                              current_tx_handle,
                                              PHY_LINK_CCA_FAIL,
                                              csma_config.csmaTries,
                                              0);
#endif
                break;
            /* Occurs when a CCA check is being retried */
            case RAIL_EVENT_TX_CCA_RETRY_SHIFT:
                break;
            /** Occurs when a clear channel assessment (CCA) is begun */
            case RAIL_EVENT_TX_START_CCA_SHIFT:
                break;

            // Scheduler Event Bitmasks: Not used

            /* Event for when the scheduler switches away from this configuration */
            case RAIL_EVENT_CONFIG_UNSCHEDULED_SHIFT:
                break;
            /* Event for when the scheduler switches to this configuration */
            case RAIL_EVENT_CONFIG_SCHEDULED_SHIFT:
                break;
            /* Event for when the status of the scheduler changes */
            case RAIL_EVENT_SCHEDULER_STATUS_SHIFT:
                break;

            // Other Event Bitmasks

            /*
            * Notifies the application that a calibration is needed.
            * It occurs whenever the RAIL library detects that a
            * calibration is needed. An application determines a valid
            * window to call \ref RAIL_Calibrate().
            */
            case RAIL_EVENT_CAL_NEEDED_SHIFT:
#ifdef MBED_CONF_RTOS_PRESENT
                osSignalSet(rf_thread_id, SL_CAL_REQ);
#else
                RAIL_Calibrate(gRailHandle, NULL, RAIL_CAL_ALL_PENDING);
#endif
                break;
            default:
                break;
            }
        }
        events = events >> 1;
        index += 1;
    }
    while (events != 0);
}
