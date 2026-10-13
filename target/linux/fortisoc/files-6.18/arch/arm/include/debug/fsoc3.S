/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Debugging macro include header for the Fortinet FortiSOC3 console UART
 *
 * The UART follows the Emma Mobile register layout (see 8250_em.c): the
 * transmit holding register is at 0x00 and accessed with byte accesses,
 * the other registers are 32 bits apart, and the line status register
 * sits one word further than in a standard 8250, at 0x18.
 */
#include <linux/serial_reg.h>

#define FSOC3_UART_LSR	0x18

		.macro	addruart, rp, rv, tmp
		ldr	\rp, =CONFIG_DEBUG_UART_PHYS
		ldr	\rv, =CONFIG_DEBUG_UART_VIRT
		.endm

		.macro	senduart, rd, rx
		strb	\rd, [\rx, #UART_TX]
		.endm

		.macro	waituarttxrdy, rd, rx
1001:		ldr	\rd, [\rx, #FSOC3_UART_LSR]
		tst	\rd, #UART_LSR_THRE
		beq	1001b
		.endm

		.macro	waituartcts, rd, rx
		.endm

		.macro	busyuart, rd, rx
1002:		ldr	\rd, [\rx, #FSOC3_UART_LSR]
		and	\rd, \rd, #UART_LSR_TEMT | UART_LSR_THRE
		teq	\rd, #UART_LSR_TEMT | UART_LSR_THRE
		bne	1002b
		.endm
