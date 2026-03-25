/**
 * heap_regions.c
 *
 * FreeRTOS heap_5 memory region definitions for STM32F439ZI.
 *
 * Region layout:
 *   Region 0 (CCM RAM, 56 KB @ 0x10000000): Task stacks + small allocs.
 *             CCM RAM is NOT DMA-accessible; safe for CPU-only use.
 *   Region 1 (SRAM BSS,  116 KB):           wolfSSL TLS + crypto buffers.
 *             mldsa87 verification needs ~60 KB contiguous – fits here.
 *
 * Total heap: 172 KB (56 + 116).
 *
 * vPortDefineHeapRegions(xPqcHeapRegions) is called automatically by
 * osKernelInitialize() because USE_FreeRTOS_HEAP_5 and
 * configHEAP_5_REGIONS = xPqcHeapRegions are defined in FreeRTOSConfig.h.
 */

#include "FreeRTOS.h"

/* ── Region 0: 56 KB in CCM RAM (uninitialized – heap_5 writes its own headers) ── */
static uint8_t ccm_heap[56 * 1024] __attribute__((section(".ccmbss")));

/* ── Region 1: 116 KB in main SRAM (BSS – zero-initialised by startup) ── */
static uint8_t sram_heap[116 * 1024];

/* Regions MUST be listed in ascending start-address order. */
HeapRegion_t xPqcHeapRegions[] = {
    { ccm_heap,  sizeof(ccm_heap)  }, /* CCM RAM: 0x10000000 */
    { sram_heap, sizeof(sram_heap) }, /* SRAM:    0x20000000+ */
    { NULL,      0                 }
};
