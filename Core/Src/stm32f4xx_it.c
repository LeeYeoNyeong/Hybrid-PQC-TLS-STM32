/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    stm32f4xx_it.c
  * @brief   Interrupt Service Routines.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stm32f4xx_it.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/
extern ETH_HandleTypeDef heth;
extern TIM_HandleTypeDef htim1;

/* USER CODE BEGIN EV */

/* USER CODE END EV */

/******************************************************************************/
/*           Cortex-M4 Processor Interruption and Exception Handlers          */
/******************************************************************************/
/**
  * @brief This function handles Non maskable interrupt.
  */
void NMI_Handler(void)
{
  /* USER CODE BEGIN NonMaskableInt_IRQn 0 */

  /* USER CODE END NonMaskableInt_IRQn 0 */
  /* USER CODE BEGIN NonMaskableInt_IRQn 1 */
   while (1)
  {
  }
  /* USER CODE END NonMaskableInt_IRQn 1 */
}

/**
  * @brief C-level fault printer. Called from naked trampoline with stacked frame pointer.
  * Stacked frame (Cortex-M4): [r0,r1,r2,r3,r12,lr,pc,xpsr]
  */
void HardFault_Handler_C(uint32_t *sp, uint32_t exc_return)
{
  extern int printf(const char *, ...);
  uint32_t cfsr  = *(volatile uint32_t *)0xE000ED28;
  uint32_t hfsr  = *(volatile uint32_t *)0xE000ED2C;
  uint32_t mmfar = *(volatile uint32_t *)0xE000ED34;
  uint32_t bfar  = *(volatile uint32_t *)0xE000ED38;
  int bfar_valid = (cfsr >> 15) & 1;
  int mmfar_valid = (cfsr >> 7) & 1;
  int fpu_basic = (exc_return & 0x10) ? 1 : 0;
  uint32_t r0 = sp[0], r1 = sp[1], r2 = sp[2], r3 = sp[3];
  uint32_t r12 = sp[4], lr_stk = sp[5], pc_stk = sp[6], xpsr = sp[7];
  printf("\n[PANIC] HardFault CFSR=0x%08lX HFSR=0x%08lX EXC=0x%08lX FP=%s\n",
         (unsigned long)cfsr, (unsigned long)hfsr,
         (unsigned long)exc_return, fpu_basic ? "basic" : "ext");
  printf("  BFAR=0x%08lX %s  MMFAR=0x%08lX %s\n",
         (unsigned long)bfar,  bfar_valid  ? "(valid)" : "(stale)",
         (unsigned long)mmfar, mmfar_valid ? "(valid)" : "(stale)");
  printf("  PC =0x%08lX  LR =0x%08lX  xPSR=0x%08lX\n",
         (unsigned long)pc_stk, (unsigned long)lr_stk, (unsigned long)xpsr);
  printf("  R0 =0x%08lX  R1 =0x%08lX  R2 =0x%08lX  R3 =0x%08lX  R12=0x%08lX\n",
         (unsigned long)r0, (unsigned long)r1, (unsigned long)r2,
         (unsigned long)r3, (unsigned long)r12);
  printf("  SP =0x%08lX  stack dump:\n", (unsigned long)sp);
  for (int i = 0; i < 16; i++) {
    printf("    [sp+%02d]=0x%08lX\n", i*4, (unsigned long)sp[i]);
  }
  *(volatile uint32_t *)0xE000ED28 = cfsr;  /* write-1-to-clear */
  while (1) {}
}

/**
  * @brief This function handles Hard fault interrupt.
  * Naked trampoline: reads correct SP before compiler prologue can modify it,
  * then tail-calls HardFault_Handler_C(sp, exc_return).
  */
__attribute__((naked)) void HardFault_Handler(void)
{
  __asm volatile (
    "mov  r1, lr        \n"  /* r1 = EXC_RETURN (bit2: 0=MSP, 1=PSP) */
    "tst  r1, #4        \n"
    "ite  eq            \n"
    "mrseq r0, msp      \n"  /* r0 = MSP if bit2=0 (handler mode or thread+MSP) */
    "mrsne r0, psp      \n"  /* r0 = PSP if bit2=1 (thread mode + PSP, FreeRTOS tasks) */
    "b    HardFault_Handler_C \n"
  );
}

/**
  * @brief This function handles Memory management fault.
  */
void MemManage_Handler(void)
{
  /* USER CODE BEGIN MemoryManagement_IRQn 0 */
  extern int printf(const char *, ...);
  volatile uint32_t cfsr  = *(volatile uint32_t *)0xE000ED28;
  volatile uint32_t mmfar = *(volatile uint32_t *)0xE000ED34;
  printf("\n[PANIC] MemManage CFSR=0x%08lX MMFAR=0x%08lX\n",
         (unsigned long)cfsr, (unsigned long)mmfar);
  /* USER CODE END MemoryManagement_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_MemoryManagement_IRQn 0 */
    /* USER CODE END W1_MemoryManagement_IRQn 0 */
  }
}

/**
  * @brief This function handles Pre-fetch fault, memory access fault.
  */
void BusFault_Handler(void)
{
  /* USER CODE BEGIN BusFault_IRQn 0 */
  extern int printf(const char *, ...);
  volatile uint32_t cfsr = *(volatile uint32_t *)0xE000ED28;
  volatile uint32_t bfar = *(volatile uint32_t *)0xE000ED38;
  printf("\n[PANIC] BusFault CFSR=0x%08lX BFAR=0x%08lX\n",
         (unsigned long)cfsr, (unsigned long)bfar);
  /* USER CODE END BusFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_BusFault_IRQn 0 */
    /* USER CODE END W1_BusFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Undefined instruction or illegal state.
  */
void UsageFault_Handler(void)
{
  /* USER CODE BEGIN UsageFault_IRQn 0 */
  extern int printf(const char *, ...);
  volatile uint32_t cfsr = *(volatile uint32_t *)0xE000ED28;
  printf("\n[PANIC] UsageFault CFSR=0x%08lX (UFSR=0x%04lX)\n",
         (unsigned long)cfsr, (unsigned long)(cfsr >> 16));
  /* USER CODE END UsageFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_UsageFault_IRQn 0 */
    /* USER CODE END W1_UsageFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Debug monitor.
  */
void DebugMon_Handler(void)
{
  /* USER CODE BEGIN DebugMonitor_IRQn 0 */

  /* USER CODE END DebugMonitor_IRQn 0 */
  /* USER CODE BEGIN DebugMonitor_IRQn 1 */

  /* USER CODE END DebugMonitor_IRQn 1 */
}

/******************************************************************************/
/* STM32F4xx Peripheral Interrupt Handlers                                    */
/* Add here the Interrupt Handlers for the used peripherals.                  */
/* For the available peripheral interrupt handler names,                      */
/* please refer to the startup file (startup_stm32f4xx.s).                    */
/******************************************************************************/

/**
  * @brief This function handles TIM1 update interrupt and TIM10 global interrupt.
  */
void TIM1_UP_TIM10_IRQHandler(void)
{
  /* USER CODE BEGIN TIM1_UP_TIM10_IRQn 0 */

  /* USER CODE END TIM1_UP_TIM10_IRQn 0 */
  HAL_TIM_IRQHandler(&htim1);
  /* USER CODE BEGIN TIM1_UP_TIM10_IRQn 1 */

  /* USER CODE END TIM1_UP_TIM10_IRQn 1 */
}

/**
  * @brief This function handles Ethernet global interrupt.
  */
void ETH_IRQHandler(void)
{
  /* USER CODE BEGIN ETH_IRQn 0 */

  /* USER CODE END ETH_IRQn 0 */
  HAL_ETH_IRQHandler(&heth);
  /* USER CODE BEGIN ETH_IRQn 1 */

  /* USER CODE END ETH_IRQn 1 */
}

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */
