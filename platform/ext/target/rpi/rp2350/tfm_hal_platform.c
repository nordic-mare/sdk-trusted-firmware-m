/*
 *  SPDX-License-Identifier: BSD-3-Clause
 *  SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#include "tfm_hal_device_header.h"
#include "tfm_peripherals_def.h"
#include "common_target_cfg.h"
#include "tfm_hal_platform.h"
#include "uart_stdout.h"
#include "region.h"
#include "region_defs.h"
#include "pico/bootrom.h"

#include "hardware/structs/psm.h"
#ifdef TFM_MULTI_CORE_TOPOLOGY
#include "platform_multicore.h"
#include "hardware/structs/sio.h"
#endif

#if defined(TFM_PARTITION_SLIH_TEST) || defined(TFM_PARTITION_FLIH_TEST)
#include "hardware/irq.h"
extern void tfm_plat_test_secure_timer_irq_handler(void);
#endif

/* The section names come from the scatter file */
REGION_DECLARE(Load$$LR$$, LR_NS_PARTITION, $$Base);
REGION_DECLARE(Image$$, ER_VENEER, $$Base);
REGION_DECLARE(Image$$, VENEER_ALIGN, $$Limit);
#ifdef BL2
REGION_DECLARE(Load$$LR$$, LR_SECONDARY_PARTITION, $$Base);
#endif /* BL2 */

const struct memory_region_limits memory_regions = {
    .non_secure_code_start =
        (uint32_t)&REGION_NAME(Load$$LR$$, LR_NS_PARTITION, $$Base) +
        BL2_HEADER_SIZE,

    .non_secure_partition_base =
        (uint32_t)&REGION_NAME(Load$$LR$$, LR_NS_PARTITION, $$Base),

    .non_secure_partition_limit =
        (uint32_t)&REGION_NAME(Load$$LR$$, LR_NS_PARTITION, $$Base) +
        NS_PARTITION_SIZE - 1,

    .veneer_base =
        (uint32_t)&REGION_NAME(Image$$, ER_VENEER, $$Base),

    .veneer_limit =
        (uint32_t)&REGION_NAME(Image$$, VENEER_ALIGN, $$Limit) - 1,

#ifdef BL2
    .secondary_partition_base =
        (uint32_t)&REGION_NAME(Load$$LR$$, LR_SECONDARY_PARTITION, $$Base),

    .secondary_partition_limit =
        (uint32_t)&REGION_NAME(Load$$LR$$, LR_SECONDARY_PARTITION, $$Base) +
        SECONDARY_PARTITION_SIZE - 1,
#endif /* BL2 */
};

extern __NO_RETURN void MemManage_Handler(void);
extern __NO_RETURN void BusFault_Handler(void);
extern __NO_RETURN void UsageFault_Handler(void);
extern __NO_RETURN void SecureFault_Handler(void);

enum tfm_hal_status_t tfm_hal_platform_init(void)
{
    NVIC_SetVector(MemoryManagement_IRQn, (uint32_t) MemManage_Handler);
    NVIC_SetVector(BusFault_IRQn, (uint32_t) BusFault_Handler);
    NVIC_SetVector(UsageFault_IRQn, (uint32_t) UsageFault_Handler);
    NVIC_SetVector(SecureFault_IRQn, (uint32_t) SecureFault_Handler);

    stdio_init();

#if defined(TFM_PARTITION_SLIH_TEST) || defined(TFM_PARTITION_FLIH_TEST)
    irq_set_exclusive_handler(TFM_TIMER0_IRQ, tfm_plat_test_secure_timer_irq_handler);
#endif

#ifdef PSA_API_TEST_IPC
    irq_set_exclusive_handler(FF_TEST_UART_IRQ, FF_TEST_UART_IRQ_Handler);
#endif

    /* Reset everything apart from ROSC and XOSC */
    hw_set_bits(&psm_hw->wdsel, PSM_WDSEL_BITS & ~(PSM_WDSEL_ROSC_BITS | PSM_WDSEL_XOSC_BITS));

    __enable_irq();
    return TFM_HAL_SUCCESS;
}

uint32_t tfm_hal_get_ns_VTOR(void)
{
    return memory_regions.non_secure_code_start;
}

uint32_t tfm_hal_get_ns_MSP(void)
{
    return *((uint32_t *)memory_regions.non_secure_code_start);
}

uint32_t tfm_hal_get_ns_entry_point(void)
{
    return *((uint32_t *)(memory_regions.non_secure_code_start + 4));
}

void tfm_hal_system_reset(void)
{
    __disable_irq();

    NVIC_SystemReset();
}

void tfm_hal_system_halt(void)
{
    __disable_irq();

#ifdef TFM_MULTI_CORE_TOPOLOGY
    /* Signal Core1 to wait for flash */
    sio_hw->doorbell_out_set = HALT_DOORBELL_MASK;
#endif

    while (1) {
        __WFE();
    }

}
