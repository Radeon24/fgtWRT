/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Entry stub of the flatkc kernel file of the x86 FortiGate appliances
 * (FortiGate 100D first).
 *
 * The stock boot loader inflates the gzip payload of the flatkc to
 * 0x100000 and jumps there in 32-bit protected mode, paging off, %esi
 * pointing to a partial Linux boot_params (the stock kernel keeps it up to
 * x86_64_start_kernel), selector 0x18 = flat data. The stub uses no stack
 * before its own GDT. It is linked at 0x100000 and assembled with:
 *
 *   gcc -m32 -c -DHDR_BIN=... -DPM_BIN=... -DCMDLINE_STR=... fortigate-stub.S
 *   ld -m elf_i386 -Ttext=0x100000 ; objcopy -O binary -j .text
 *
 * HDR_BIN: setup header of the bzImage (from offset 0x1f1);
 * PM_BIN: protected-mode part of the bzImage (after the setup sectors).
 *
 * What it does:
 *  1. flat GDT of its own (0x10 code, 0x18 data, as in the Linux boot
 *     protocol), own stack;
 *  2. prints on COM1 (0x3f8, speed left by the boot loader) the %esi it
 *     got, the "HdrS" signature and the e820 entry count of the boot_params
 *     of the boot loader: diagnostics of the first boot;
 *  3. builds a NEW zero page (no blind copy): only the e820 entries
 *     (0x1e8/0x2d0) and alt_mem_k (0x1e0) of the boot loader are taken,
 *     after checks (at most 128 entries, types 1 to 20); otherwise a safe
 *     e820 table: 0-0x9f000 and 1 MiB-512 MiB;
 *  4. copies the setup header of OUR bzImage (kernel_alignment, init_size
 *     read by the decompressor), type_of_loader 0xff, LOADED_HIGH,
 *     code32_start, no external initrd, cmd_line_ptr = our command line
 *     (appended by the kernel to its built-in one);
 *  5. jumps to startup_32 of the protected-mode part of the bzImage
 *     (included at 0x4000), %esi = zero page.
 * No hardware access but the COM1 serial port.
 *
 * With -DRELAY_RD, the initrd of the boot loader is handed to the kernel
 * (ramdisk_image/ramdisk_size of the zero page) instead of being ignored:
 * the boot loader loads the "rootfs.gz" file of the container at
 * 0x1000000 and gives its address and size at 0x218/0x21c of its
 * boot_params, that is where the decompressor of the kernel runs
 * ([pref_address, pref_address + init_size) of our setup header). The
 * initrd is then copied (in RAM only) to the first 2 MiB boundary above
 * both its end and that area, after checks: source and destination
 * entirely inside a RAM entry of the e820 table of the zero page, end at
 * most initrd_addr_max (0x22c). A relayed initrd that would still overlap
 * the area of the decompressor stops the stub (hlt, no jump). Any other
 * refusal leaves the initrd fields at 0 and jumps to the kernel, but with
 * -DRELAY_STRICT, for a kernel that has no other root file system:
 *  - any refusal, and a missing initrd, stop the stub (hlt) instead of
 *    booting a kernel that would panic and reboot in a loop;
 *  - initrd_addr_max is also checked for an initrd relayed in place;
 *  - the default e820 table of the stub (the one of the boot loader
 *    rejected) is refused: it is a guess, not a proof of RAM;
 *  - a zone that overlaps an e820 entry of another type than RAM is
 *    refused, even if a RAM entry covers it.
 */
#if defined(RELAY_STRICT) && !defined(RELAY_RD)
#error "RELAY_STRICT needs RELAY_RD"
#endif
	.code32
	.text
	.globl	_start

#define BASE		0x100000
#define ZP		(BASE + 0x1000)		/* zero page (4 KiB) */
#define STACK_TOP	(BASE + 0x3000)
#define KERNEL		(BASE + 0x4000)		/* protected-mode part of the bzImage */
#define COM1		0x3f8

	.macro	MSG lbl
	movl	$\lbl, %esi
	call	puts
	.endm

_start:
	cli
	cld
	movl	%esi, %edx			/* boot_params of the boot loader */
	movl	$0x18, %eax			/* as the stock kernel, before any GDT */
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	lgdtl	gdtr
	ljmp	$0x10, $1f
1:	movl	$0x18, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss
	movl	$STACK_TOP, %esp

	MSG	m_hello
	movl	%edx, %eax
	call	puthex
	movl	%edx, %ebp			/* %ebp = boot_params of the boot loader (0: none) */
	testl	%ebp, %ebp
	jz	2f
	MSG	m_hdrs
	movl	0x202(%ebp), %eax		/* "HdrS" = 0x53726448 with a Linux header */
	call	puthex
	MSG	m_e820
	movzbl	0x1e8(%ebp), %eax
	call	puthex
	MSG	m_cmd
	movl	0x228(%ebp), %eax		/* cmd_line_ptr of the boot loader */
	call	puthex
2:
	/* 3. new zero page */
	movl	$ZP, %ebx
	movl	%ebx, %edi
	xorl	%eax, %eax
	movl	$1024, %ecx
	rep stosl
	testl	%ebp, %ebp
	jz	e820_default
	movzbl	0x1e8(%ebp), %ecx
	testl	%ecx, %ecx
	jz	e820_default
	cmpl	$128, %ecx
	ja	e820_default
	leal	0x2d0(%ebp), %esi		/* check the types (u32 at +16 of each 20-byte entry) */
	movl	%ecx, %eax
3:	movl	16(%esi), %edi
	testl	%edi, %edi
	jz	e820_default
	cmpl	$20, %edi
	ja	e820_default
	addl	$20, %esi
	decl	%eax
	jnz	3b
	movb	%cl, 0x1e8(%ebx)		/* take count, table, alt_mem_k */
	imull	$20, %ecx
	leal	0x2d0(%ebp), %esi
	leal	0x2d0(%ebx), %edi
	rep movsb
	movl	0x1e0(%ebp), %eax
	movl	%eax, 0x1e0(%ebx)
	MSG	m_e820_bios
	jmp	4f
e820_default:
	movl	$0x9f000, 0x2d8(%ebx)		/* [0] 0 + 0x9f000, RAM */
	movl	$1, 0x2e0(%ebx)
	movl	$0x100000, 0x2e4(%ebx)		/* [1] 1 MiB + 511 MiB, RAM */
	movl	$0x1ff00000, 0x2ec(%ebx)
	movl	$1, 0x2f4(%ebx)
	movb	$2, 0x1e8(%ebx)
#ifdef RELAY_STRICT
	movb	$1, e820_def			/* refused by relay_rd */
#endif
	MSG	m_e820_def
4:
	/* 4. setup header of our bzImage */
	movl	$hdr_blob, %esi
	leal	0x1f1(%ebx), %edi
	movl	$(hdr_end - hdr_blob), %ecx
	rep movsb
	movb	$0xff, 0x210(%ebx)		/* type_of_loader: undefined */
	orb	$0x01, 0x211(%ebx)		/* loadflags: LOADED_HIGH */
	movl	$KERNEL, 0x214(%ebx)		/* code32_start */
	movl	$0, 0x218(%ebx)			/* ramdisk_image */
	movl	$0, 0x21c(%ebx)			/* ramdisk_size */
	movl	$cmdline, 0x228(%ebx)		/* cmd_line_ptr */
#ifdef RELAY_RD
	call	relay_rd
#endif

	/* 5. jump */
	MSG	m_go
	movl	%ebx, %esi
	xorl	%ebp, %ebp
	xorl	%edi, %edi
	jmp	KERNEL

/* --- COM1 serial port (no endless wait: without a UART, inb returns 0xff) --- */
putc:					/* %al */
	pushl	%ecx
	pushl	%edx
	pushl	%eax
	movl	$0x100000, %ecx
	movw	$(COM1 + 5), %dx
5:	inb	%dx, %al
	testb	$0x20, %al
	jnz	6f
	loop	5b
6:	popl	%eax
	movw	$COM1, %dx
	outb	%al, %dx
	popl	%edx
	popl	%ecx
	ret
puts:					/* %esi = string */
	pushl	%eax
7:	lodsb
	testb	%al, %al
	jz	8f
	call	putc
	jmp	7b
8:	popl	%eax
	ret
puthex:					/* %eax, 8 digits */
	pushl	%ecx
	pushl	%edx
	movl	%eax, %edx
	movl	$8, %ecx
9:	roll	$4, %edx
	movl	%edx, %eax
	andl	$0xf, %eax
	cmpb	$10, %al
	jb	10f
	addb	$('a' - 10 - '0'), %al
10:	addb	$'0', %al
	call	putc
	loop	9b
	popl	%edx
	popl	%ecx
	ret

#ifdef RELAY_RD
/* in_ram: [%eax, %eax + %ecx) entirely inside ONE entry of type 1 (RAM)
 * below 4 GiB of an e820 table (%esi, %edx 20-byte entries, %edx <= 128);
 * CF = 0 if so, 1 if not (size 0 or overflow included). With RELAY_STRICT,
 * CF = 1 too if an entry of another type overlaps the zone. Reads the
 * table only; registers preserved. */
in_ram:
	pushl	%ebx
	pushl	%edi
	pushl	%esi
	pushl	%edx
	testl	%ecx, %ecx
	jz	ir_no
	movl	%eax, %ebx
	addl	%ecx, %ebx			/* %ebx = end (excluded) */
	jc	ir_no
ir_loop:
	testl	%edx, %edx
	jz	ir_no
	cmpl	$1, 16(%esi)			/* RAM */
	jne	ir_next
	cmpl	$0, 4(%esi)			/* address below 4 GiB */
	jne	ir_next
	cmpl	(%esi), %eax			/* start >= start of the entry */
	jb	ir_next
	cmpl	$0, 12(%esi)			/* entry of 4 GiB or more: contains */
	jne	ir_yes
	movl	(%esi), %edi
	addl	8(%esi), %edi			/* end of the entry; carry: above 4 GiB */
	jc	ir_yes
	cmpl	%edi, %ebx
	jbe	ir_yes
ir_next:
	addl	$20, %esi
	decl	%edx
	jmp	ir_loop
ir_yes:
#ifdef RELAY_STRICT
	/* no entry of type != 1 may overlap [%eax, %ebx) (below 4 GiB) */
	movl	4(%esp), %esi			/* table and count of the caller */
	movl	(%esp), %edx
ir_ov:
	testl	%edx, %edx
	jz	ir_ok
	cmpl	$1, 16(%esi)
	je	ir_ovn
	cmpl	$0, 4(%esi)			/* entry at 4 GiB or above: disjoint */
	jne	ir_ovn
	cmpl	(%esi), %ebx			/* zone ends before the entry: disjoint */
	jbe	ir_ovn
	cmpl	$0, 12(%esi)			/* entry of 4 GiB or more: overlaps */
	jne	ir_no
	movl	(%esi), %edi
	addl	8(%esi), %edi			/* end of the entry; carry: overlaps */
	jc	ir_no
	cmpl	%edi, %eax			/* zone starts after the entry: disjoint */
	jb	ir_no
ir_ovn:
	addl	$20, %esi
	decl	%edx
	jmp	ir_ov
ir_ok:
#endif
	clc
	jmp	ir_out
ir_no:
	stc
ir_out:
	popl	%edx
	popl	%esi
	popl	%edi
	popl	%ebx
	ret

/* relay_rd: %ebx = zero page (e820 and our setup header already there),
 * %ebp = boot_params of the boot loader (0: none). Hands the initrd of
 * the boot loader to the kernel, after a copy out of the area of the
 * decompressor if needed. Registers preserved, unless it stops. */
relay_rd:
	pushal
	testl	%ebp, %ebp
	jz	rl_none
	movl	0x218(%ebp), %eax
	movl	0x21c(%ebp), %ecx
	movl	%eax, rd_src
	movl	%ecx, rd_len
	testl	%ecx, %ecx
	jz	rl_none
#ifdef RELAY_STRICT
	cmpb	$0, e820_def			/* default e820: a guess */
	jne	rl_e820def
#endif
	leal	0x2d0(%ebx), %esi		/* e820 of the zero page, as the kernel sees it */
	movzbl	0x1e8(%ebx), %edx
	call	in_ram
	jc	rl_src_out
	cmpl	$0, 0x25c(%ebx)			/* pref_address below 4 GiB */
	jne	rl_area
	movl	0x258(%ebx), %edi		/* area of the decompressor [pref, pref + init_size) */
	movl	%edi, rd_kz
	addl	0x260(%ebx), %edi
	jc	rl_area
	movl	%edi, rd_kze
	movl	rd_src, %eax
	movl	%eax, %edx
	addl	rd_len, %edx			/* %edx = end of the source (no carry: in_ram) */
	cmpl	rd_kz, %edx
	jbe	rl_place			/* source below the area */
	cmpl	rd_kze, %eax
	jae	rl_place			/* source above the area */
	/* copy: destination = max(end of the source, end of the area), rounded up to 2 MiB */
	cmpl	%edi, %edx
	jae	20f
	movl	%edi, %edx
20:	addl	$0x1fffff, %edx
	jc	rl_dst_out
	andl	$0xffe00000, %edx
	movl	%edx, rd_dst
	movl	%edx, %eax
	movl	rd_len, %ecx
	leal	0x2d0(%ebx), %esi
	movzbl	0x1e8(%ebx), %edx
	call	in_ram
	jc	rl_dst_out
	movl	rd_dst, %eax
	addl	rd_len, %eax
	decl	%eax				/* last byte */
	cmpl	0x22c(%ebx), %eax		/* initrd_addr_max */
	ja	rl_max
	movl	rd_src, %esi			/* disjoint: destination >= end of the source */
	movl	rd_dst, %edi
	movl	rd_len, %ecx
	movl	%ecx, %edx
	shrl	$2, %ecx
	rep movsl
	movl	%edx, %ecx
	andl	$3, %ecx
	rep movsb
	jmp	rl_guard
rl_place:
	movl	rd_src, %eax
	movl	%eax, rd_dst
#ifdef RELAY_STRICT
	addl	rd_len, %eax			/* same check as the copy (no carry: in_ram) */
	decl	%eax
	cmpl	0x22c(%ebx), %eax		/* initrd_addr_max */
	ja	rl_max
#endif
rl_guard:
	/* [dst, dst + size) must not overlap [pref, pref + init_size): else stop */
	movl	rd_dst, %eax
	movl	%eax, %ecx
	addl	rd_len, %ecx
	cmpl	rd_kz, %ecx
	jbe	rl_ok
	cmpl	rd_kze, %eax
	jae	rl_ok
	MSG	m_rl_overlap
	jmp	halt
rl_ok:
	movl	rd_dst, %eax
	movl	%eax, 0x218(%ebx)		/* ramdisk_image */
	movl	rd_len, %ecx
	movl	%ecx, 0x21c(%ebx)		/* ramdisk_size */
	MSG	m_rl_ok
	movl	rd_src, %eax
	call	puthex
	MSG	m_rl_arrow
	movl	rd_dst, %eax
	call	puthex
	MSG	m_rl_plus
	movl	rd_len, %eax
	call	puthex
	MSG	m_rl_area
	movl	rd_kz, %eax
	call	puthex
	MSG	m_rl_dash
	movl	rd_kze, %eax
	call	puthex
	jmp	rl_out
rl_none:
	MSG	m_rl_none
#ifdef RELAY_STRICT
	jmp	halt				/* no root file system without it */
#endif
	jmp	rl_out				/* nothing to relay: not a refusal */
#ifdef RELAY_STRICT
rl_e820def:
	MSG	m_rl_e820def
	jmp	rl_refused
#endif
rl_src_out:
	MSG	m_rl_src
	jmp	rl_refused
rl_area:
	MSG	m_rl_areak
	jmp	rl_refused
rl_dst_out:
	MSG	m_rl_dst
	jmp	rl_refused
rl_max:
	MSG	m_rl_max
rl_refused:
#ifdef RELAY_STRICT
	jmp	halt
#endif
	MSG	m_rl_not			/* fields left at 0 */
rl_out:
	popal
	ret

halt:
	MSG	m_halt
21:	cli
	hlt
	jmp	21b

	.balign	4
rd_src:	.long	0
rd_len:	.long	0
rd_dst:	.long	0
rd_kz:	.long	0
rd_kze:	.long	0
#ifdef RELAY_STRICT
e820_def:	.byte	0
#endif
#endif

	.balign	8
gdt:	.quad	0
	.quad	0
	.quad	0x00cf9a000000ffff		/* 0x10: flat 32-bit code */
	.quad	0x00cf92000000ffff		/* 0x18: flat data */
gdt_end:
gdtr:	.word	gdt_end - gdt - 1
	.long	gdt

m_hello:	.asciz	"\r\nfgtwrt x86-stub : esi="
m_hdrs:		.asciz	" HdrS="
m_e820:		.asciz	" e820="
m_cmd:		.asciz	" cmd="
m_e820_bios:	.asciz	"\r\nfgtwrt x86-stub : e820 from the boot loader"
m_e820_def:	.asciz	"\r\nfgtwrt x86-stub : DEFAULT e820 (1-512 MiB)"
m_go:		.asciz	" -> startup_32\r\n"
#ifdef RELAY_RD
m_rl_ok:	.asciz	"\r\nfgtwrt x86-stub : initrd relayed "
m_rl_arrow:	.asciz	" -> "
m_rl_plus:	.asciz	" +"
m_rl_area:	.asciz	" kernel area "
m_rl_dash:	.asciz	"-"
m_rl_none:	.asciz	"\r\nfgtwrt x86-stub : no initrd, nothing to relay"
m_rl_src:	.asciz	"\r\nfgtwrt x86-stub : REFUSED: initrd source outside e820 RAM"
m_rl_areak:	.asciz	"\r\nfgtwrt x86-stub : REFUSED: kernel area (pref_address/init_size)"
m_rl_dst:	.asciz	"\r\nfgtwrt x86-stub : REFUSED: destination outside e820 RAM"
m_rl_max:	.asciz	"\r\nfgtwrt x86-stub : REFUSED: destination above initrd_addr_max"
m_rl_not:	.asciz	"\r\nfgtwrt x86-stub : initrd NOT relayed (fields left at 0)"
m_rl_overlap:	.asciz	"\r\nfgtwrt x86-stub : HALT: initrd overlaps the kernel area"
m_halt:		.asciz	"\r\nfgtwrt x86-stub : HALT (hlt)\r\n"
#ifdef RELAY_STRICT
m_rl_e820def:	.asciz	"\r\nfgtwrt x86-stub : REFUSED: default e820 (the one of the boot loader rejected)"
#endif
#endif
cmdline:	.asciz	CMDLINE_STR
hdr_blob:	.incbin	HDR_BIN
hdr_end:

	.org	0x1000				/* zero page, stack: zeros in the file */
	.fill	0x3000, 1, 0
	.org	0x4000
	.incbin	PM_BIN				/* protected-mode part of the bzImage */
