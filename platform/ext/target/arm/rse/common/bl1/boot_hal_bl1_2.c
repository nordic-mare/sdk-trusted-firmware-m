/*
 * Copyright (c) 2019-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "boot_hal.h"
#include "region.h"
#include "device_definition.h"
#include "Driver_Flash.h"
#include "flash_layout.h"
#include "host_base_address.h"
#include "region_defs.h"
#include "platform_base_address.h"
#include "uart_stdout.h"
#include "tfm_plat_otp.h"
#include "trng.h"
#include "kmu_drv.h"
#include "platform_regs.h"
#ifdef CRYPTO_HW_ACCELERATOR
#include "fih.h"
#include "cc3xx_drv.h"
#endif /* CRYPTO_HW_ACCELERATOR */
#include <string.h>
#include "cmsis_compiler.h"
#ifdef RSE_USE_HOST_FLASH
#include "fip_parser.h"
#include "host_flash_atu.h"
#include "plat_def_fip_uuid.h"
#endif
#include "tfm_plat_nv_counters.h"
#include "rse_kmu_keys.h"
#include "mpu_armv8m_drv.h"
#include "tfm_hal_device_header.h"
#include "dpa_hardened_word_copy.h"
#include "rse_clocks.h"
#if RSE_AMOUNT > 1
#include "rse_handshake.h"
#endif

#ifdef PLATFORM_PSA_ADAC_SECURE_DEBUG
#include <stdbool.h>
#include "target_cfg.h"
#include "platform_dcu.h"

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

#endif /* PLATFORM_PSA_ADAC_SECURE_DEBUG */

//TODO: This debug state needs be a context parameter for IAK derivation
uint32_t debug_state = 0;
struct mpu_armv8m_dev_t dev_mpu_s = { MPU_BASE };

uint32_t image_offsets[2];

/* Flash device name must be specified by target */
extern ARM_DRIVER_FLASH FLASH_DEV_NAME;

#ifdef RSE_USE_ROM_LIB_FROM_SRAM
extern uint32_t __got_start__;
extern uint32_t __got_end__;
#endif /* RSE_USE_ROM_LIB_FROM_SRAM */

REGION_DECLARE(Image$$, ARM_LIB_STACK, $$ZI$$Base);

#ifdef RSE_USE_HOST_FLASH
uint32_t bl1_image_get_flash_offset(uint32_t image_id)
{
    switch (image_id) {
    case 0:
        return HOST_FLASH0_IMAGE0_BASE_S - FLASH_BASE_ADDRESS + image_offsets[0];
    case 1:
        return HOST_FLASH0_IMAGE1_BASE_S - FLASH_BASE_ADDRESS + image_offsets[1];
    default:
        FIH_PANIC;
    }
}
#endif

static int32_t init_atu_regions(void)
{
#ifdef RSE_USE_HOST_UART
    enum atu_error_t atu_err;

    /* Initialize UART region */
    atu_err = atu_initialize_region(&ATU_DEV_S,
                                get_supported_region_count(&ATU_DEV_S) - 1,
                                HOST_UART0_BASE_NS, HOST_UART_BASE,
                                HOST_UART_SIZE);
    if (atu_err != ATU_ERR_NONE) {
        return atu_err;
    }
#endif /* RSE_USE_HOST_UART */

    return 0;
}

#ifdef PLATFORM_PSA_ADAC_SECURE_DEBUG
static void read_debug_state_from_reset_syndrome(void)
{
    struct rse_sysctrl_t *sysctrl = (struct rse_sysctrl_t *)RSE_SYSCTRL_BASE_S;
    uint32_t reg_value = sysctrl->reset_syndrome;

    /* Bits 24:31 (SWSYN) are allocated for software defined reset syndrome */
    reg_value = (reg_value >> 24) & 0xFF;

    /* Use last TFM_PLAT_LAST_CCA_ADAC_ZONE number of bits of
     * RESET_SYNDROME.SWSYN register for conveying debug state information
     */
    uint16_t read_mask = (1 << TFM_PLAT_LAST_CCA_ADAC_ZONE) -1;
    debug_state = reg_value & read_mask;
}

static int32_t tfm_plat_select_and_apply_debug_permissions(void)
{
    if (CHECK_BIT(debug_state, TFM_PLAT_CCA_ADAC_ZONE1 - 1)) {
        return tfm_plat_apply_debug_permissions(TFM_PLAT_CCA_ADAC_ZONE1);
    }

    if (CHECK_BIT(debug_state, TFM_PLAT_CCA_ADAC_ZONE2 - 1)) {
        return tfm_plat_apply_debug_permissions(TFM_PLAT_CCA_ADAC_ZONE2);

    } else {
        return 0;
    }
}

static int32_t debug_preconditions_check(bool *valid_debug_conditions)
{
    enum tfm_plat_err_t plat_err;
    enum plat_otp_lcs_t lcs;

    /* Read LCS from OTP */
    plat_err = tfm_plat_otp_read(PLAT_OTP_ID_LCS, sizeof(lcs), (uint8_t*)&lcs);
    if (plat_err != TFM_PLAT_ERR_SUCCESS) {
        return plat_err;
    }

    *valid_debug_conditions = (lcs == PLAT_OTP_LCS_SECURED) ? true : false;

    return 0;
}

static int32_t boot_platform_init_debug(void)
{
    int32_t rc;
    bool valid_debug_conditions;

    rc = debug_preconditions_check(&valid_debug_conditions);
    if (rc != 0) {
        return rc;
    }

    if (valid_debug_conditions) {
        /* Read debug state from reset syndrome register */
        read_debug_state_from_reset_syndrome();
        /* Apply required debug permissions */
        rc = tfm_plat_select_and_apply_debug_permissions();
        if (rc != 0) {
            return rc;
        }
    }
    /* Lock DCU so that debug permissions cannot be updated during current
     * power cycle
     */
    return tfm_plat_lock_dcu();
}
#endif /* PLATFORM_PSA_ADAC_SECURE_DEBUG */

#ifdef RSE_SUPPORT_ROM_LIB_RELOCATION
static void setup_got_register(void)
{
    __asm volatile(
        "mov r9, %0 \n"
        "mov r2, %1 \n"
        "lsl r9, #16 \n"
        "orr r9, r9, r2 \n"
        : : "I" (BL1_1_DATA_START >> 16), "I" (BL1_1_DATA_START & 0xFFFF) : "r2"
    );
}
#endif /* RSE_SUPPORT_ROM_LIB_RELOCATION */

#ifdef RSE_USE_ROM_LIB_FROM_SRAM
static void copy_rom_library_into_sram(void)
{
    uint32_t got_entry;

    /* Copy the ROM into VM1 */
    memcpy((uint8_t *)VM1_BASE_S, (uint8_t *)ROM_BASE_S, BL1_1_CODE_SIZE);

    /* Patch the GOT so that any address which pointed into ROM now points into
     * VM1.
     */
    for (uint32_t * addr = &__got_start__; addr < &__got_end__; addr++) {
        got_entry = *addr;

        if (got_entry >= ROM_BASE_S && got_entry < ROM_BASE_S + ROM_SIZE) {
            got_entry -= ROM_BASE_S;
            got_entry += VM1_BASE_S;
        }
    }
}
#endif /* RSE_USE_ROM_LIB_FROM_SRAM */

/* bootloader platform-specific hw initialization */
int32_t boot_platform_init(void)
{
    int32_t result;
    enum tfm_plat_err_t plat_err;

#ifdef RSE_SUPPORT_ROM_LIB_RELOCATION
    setup_got_register();
#endif /* RSE_SUPPORT_ROM_LIB_RELOCATION */
#ifdef RSE_USE_ROM_LIB_FROM_SRAM
    copy_rom_library_into_sram();
#endif /* RSE_USE_ROM_LIB_FROM_SRAM */

    /* Initialize stack limit register */
    uint32_t msp_stack_bottom =
            (uint32_t)&REGION_NAME(Image$$, ARM_LIB_STACK, $$ZI$$Base);

    __set_MSPLIM(msp_stack_bottom);

    /* Early clock config to speed up boot */
    result = rse_clock_config();
    if (result != 0) {
        return result;
    }
    SystemCoreClockUpdate();

    plat_err = tfm_plat_init_nv_counter();
    if (plat_err != TFM_PLAT_ERR_SUCCESS) {
        return plat_err;
    }

    result = init_atu_regions();
    if (result != 0) {
        return result;
    }

#if defined(TFM_BL1_LOGGING) || defined(TEST_BL1_1) || defined(TEST_BL1_2)
    stdio_init();
#endif /* defined(TFM_BL1_LOGGING) || defined(TEST_BL1_1) || defined(TEST_BL1_2) */

    result = FLASH_DEV_NAME.Initialize(NULL);
    if (result != ARM_DRIVER_OK) {
        return result;
    }

#ifdef RSE_USE_HOST_FLASH
    result = host_flash_atu_init_regions_for_image(UUID_RSE_FIRMWARE_BL2, image_offsets);
    if (result != 0) {
        return result;
    }
#endif

    return 0;
}

int32_t boot_platform_post_init(void)
{
    int32_t rc;
    enum tfm_plat_err_t plat_err;

    uint32_t vhuk_seed[8 * RSE_AMOUNT];
    size_t vhuk_seed_len;

    plat_err = rse_derive_vhuk_seed(vhuk_seed, sizeof(vhuk_seed), &vhuk_seed_len);
    if (plat_err != TFM_PLAT_ERR_SUCCESS) {
        return plat_err;
    }

#if RSE_AMOUNT > 1
    rc = rse_handshake(vhuk_seed);
    if (rc != 0) {
        return rc;
    }
#endif /* RSE_AMOUNT > 1 */

    plat_err = rse_setup_vhuk((uint8_t *)vhuk_seed, vhuk_seed_len);
    if (plat_err) {
        return plat_err;
    }

    plat_err = rse_setup_cpak_seed();
    if (plat_err) {
        return plat_err;
    }

#ifdef RSE_BOOT_KEYS_CCA
    plat_err = rse_setup_dak_seed();
    if (plat_err) {
        return plat_err;
    }
#endif
#ifdef RSE_BOOT_KEYS_DPE
    plat_err = rse_setup_rot_cdi();
    if (plat_err) {
        return plat_err;
    }
#endif

    plat_err = rse_setup_runtime_secure_image_encryption_key();
    if (plat_err) {
        return plat_err;
    }

    plat_err = rse_setup_runtime_non_secure_image_encryption_key();
    if (plat_err) {
        return plat_err;
    }

#ifdef PLATFORM_PSA_ADAC_SECURE_DEBUG
    rc = boot_platform_init_debug();
    if (rc != 0) {
        return rc;
    }
#endif /* PLATFORM_PSA_ADAC_SECURE_DEBUG */

    return 0;
}


static int invalidate_hardware_keys(void)
{
    enum kmu_error_t kmu_err;
    uint32_t slot;

    for (slot = 0; slot < KMU_USER_SLOT_MIN; slot++) {
        kmu_err = kmu_set_slot_invalid(&KMU_DEV_S, slot);
        if (kmu_err != KMU_ERROR_NONE) {
            return kmu_err;
        }
    }

    return 0;
}

static int disable_rom_execution(void)
{
    int rc;
    struct mpu_armv8m_region_cfg_t rom_region_config = {
        0,
        ROM_BASE_S,
        ROM_BASE_S + ROM_SIZE - 1,
        MPU_ARMV8M_MAIR_ATTR_CODE_IDX,
        MPU_ARMV8M_XN_EXEC_NEVER,
        MPU_ARMV8M_AP_RO_PRIV_ONLY,
        MPU_ARMV8M_SH_NONE,
#ifdef TFM_PXN_ENABLE
        MPU_ARMV8M_PRIV_EXEC_NEVER,
#endif
    };

    rc = mpu_armv8m_region_enable(&dev_mpu_s, &rom_region_config);
    if (rc != 0) {
        return rc;
    }

    return mpu_armv8m_enable(&dev_mpu_s, PRIVILEGED_DEFAULT_ENABLE,
                             HARDFAULT_NMI_ENABLE);
}

void boot_platform_quit(struct boot_arm_vector_table *vt)
{
    /* Clang at O0, stores variables on the stack with SP relative addressing.
     * When manually set the SP then the place of reset vector is lost.
     * Static variables are stored in 'data' or 'bss' section, change of SP has
     * no effect on them.
     */
    static struct boot_arm_vector_table *vt_cpy;
    int32_t result;

#ifdef RSE_USE_HOST_FLASH
    result = host_flash_atu_uninit_regions();
    if (result) {
        while(1){}
    }
#endif

#ifdef CRYPTO_HW_ACCELERATOR
    result = cc3xx_lowlevel_uninit();
    if (result) {
        while (1);
    }
#endif /* CRYPTO_HW_ACCELERATOR */

    result = FLASH_DEV_NAME.Uninitialize();
    if (result != ARM_DRIVER_OK) {
        while (1){}
    }

#if defined(TFM_BL1_LOGGING) || defined(TEST_BL1_1) || defined(TEST_BL1_2)
    stdio_uninit();
#endif /* defined(TFM_BL1_LOGGING) || defined(TEST_BL1_1) || defined(TEST_BL1_2) */

    kmu_random_delay(&KMU_DEV_S, KMU_DELAY_LIMIT_32_CYCLES);

    result = disable_rom_execution();
    if (result != 0) {
        while (1);
    }

    vt_cpy = vt;
#if defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8M_BASE__) \
 || defined(__ARM_ARCH_8_1M_MAIN__)
    /* Restore the Main Stack Pointer Limit register's reset value
     * before passing execution to runtime firmware to make the
     * bootloader transparent to it.
     */
    __set_MSPLIM(0);
#endif /* defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8M_BASE__) \
       || defined(__ARM_ARCH_8_1M_MAIN__) */

    __set_MSP(vt_cpy->msp);
    __DSB();
    __ISB();

    boot_jump_to_next_image(vt_cpy->reset);
}

int boot_platform_pre_load(uint32_t image_id)
{
    kmu_random_delay(&KMU_DEV_S, KMU_DELAY_LIMIT_32_CYCLES);

    return 0;
}

int boot_platform_post_load(uint32_t image_id)
{
    int rc;

    rc = invalidate_hardware_keys();
    if (rc != 0) {
        return rc;
    }

    return 0;
}
