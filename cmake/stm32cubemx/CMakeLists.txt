cmake_minimum_required(VERSION 3.22)
# Enable CMake support for ASM and C languages
enable_language(C ASM)
# STM32CubeMX generated symbols (macros)
set(MX_Defines_Syms 
	USE_HAL_DRIVER 
	STM32F439xx
    $<$<CONFIG:Debug>:DEBUG>
)

# STM32CubeMX generated include paths
set(MX_Include_Dirs
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Inc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wolfSSL
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Inc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Inc/Legacy
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/CMSIS_RTOS_V2
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM4F
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/CMSIS/Device/ST/STM32F4xx/Include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/CMSIS/Include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/
)

# STM32CubeMX generated application sources
set(MX_Application_Src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/freertos.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/stm32f4xx_it.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/stm32f4xx_hal_msp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/stm32f4xx_hal_timebase_tim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/sysmem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/syscalls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../startup_stm32f439xx.s
)

# STM32 HAL/LL Drivers
set(STM32_Drivers_Src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Core/Src/system_stm32f4xx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_tim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_tim_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_cryp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_cryp_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rcc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rcc_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_flash_ramfunc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_gpio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_dma_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_dma.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pwr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pwr_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_cortex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_exti.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_eth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_hash_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rng.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rtc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_rtc_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_uart.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_pcd_ex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_ll_usb.c
)

# Drivers Midllewares


set(FreeRTOS_Src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/croutine.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/event_groups.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/list.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/queue.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/stream_buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/tasks.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/timers.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/CMSIS_RTOS_V2/cmsis_os2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/portable/MemMang/heap_4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM4F/port.c
)
set(wolfSSL_Src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/aes.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/arc4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/asm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/asn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/blake2b.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/blake2s.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/camellia.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/chacha.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/chacha20_poly1305.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/cmac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/coding.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/compress.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/cryptocb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/cpuid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/curve448.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/curve25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/des3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/dh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/dilithium.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/dsa.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ecc_fp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ecc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/eccsi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ed448.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ed25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/evp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ext_mlkem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/fe_448.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/fe_low_mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/fe_operations.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ge_448.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ge_low_mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ge_operations.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/hmac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/hpke.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/integer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/kdf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/logging.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/md2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/md4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/md5.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/misc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/memory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/pkcs7.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/pkcs12.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/poly1305.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/pwdbased.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/random.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/rc2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/ripemd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/rsa.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sakke.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sha.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sha3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sha512.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/signature.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_arm32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_arm64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_armthumb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_c32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_c64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_cortexm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_dsp32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_int.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/sp_x86_64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/srp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/tfm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_dsp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_encrypt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_mlkem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_mlkem_poly.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_lms.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_lms_impl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_pkcs11.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_port.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_xmss.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wc_xmss_impl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wolfevent.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/wolfmath.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/armv8-32-curve25519_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/armv8-32-sha512-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/armv8-aes.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/armv8-curve25519_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/armv8-sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/armv8-sha512.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-chacha-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-curve25519_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-mlkem-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-poly1305-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-sha3-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/arm/thumb2-sha512-asm_c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/atmel/atmel.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/st/stm32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/src/port/st/stsafe.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/IDE/STM32Cube/wolfssl_example.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/test/test.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/wolfcrypt/benchmark/benchmark.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/bio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/conf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/crl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/dtls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/dtls13.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/internal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/keys.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ocsp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/pk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/quic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/sniffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_asn1.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_bn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_certman.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_crypto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_load.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_misc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_p7p12.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_sess.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/ssl_sk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/tls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/tls13.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/wolfio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/x509.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/src/x509_str.c
)

# Link directories setup
set(MX_LINK_DIRS

)
# Project static libraries
set(MX_LINK_LIBS 
    STM32_Drivers
    ${TOOLCHAIN_LINK_LIBRARIES}
    FreeRTOS	wolfSSL	
)
# Interface library for includes and symbols
add_library(stm32cubemx INTERFACE)
target_include_directories(stm32cubemx INTERFACE ${MX_Include_Dirs})
target_compile_definitions(stm32cubemx INTERFACE ${MX_Defines_Syms})

# Create STM32_Drivers static library
add_library(STM32_Drivers OBJECT)
target_sources(STM32_Drivers PRIVATE ${STM32_Drivers_Src})
target_link_libraries(STM32_Drivers PUBLIC stm32cubemx)


# Create FreeRTOS static library
add_library(FreeRTOS OBJECT)
target_sources(FreeRTOS PRIVATE ${FreeRTOS_Src})
target_link_libraries(FreeRTOS PUBLIC stm32cubemx)

# Create wolfSSL static library
add_library(wolfSSL OBJECT)
target_sources(wolfSSL PRIVATE ${wolfSSL_Src})
target_link_libraries(wolfSSL PUBLIC stm32cubemx)

# Add STM32CubeMX generated application sources to the project
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${MX_Application_Src})

# Link directories setup
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE ${MX_LINK_DIRS})

# Add libraries to the project
target_link_libraries(${CMAKE_PROJECT_NAME} ${MX_LINK_LIBS})

# Add the map file to the list of files to be removed with 'clean' target
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES ADDITIONAL_CLEAN_FILES ${CMAKE_PROJECT_NAME}.map)

# Validate that STM32CubeMX code is compatible with C standard
if((CMAKE_C_STANDARD EQUAL 90) OR (CMAKE_C_STANDARD EQUAL 99))
    message(ERROR "Generated code requires C11 or higher")
endif()
